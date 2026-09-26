---
name: mcp
description: >-
  Реализация MCP-сервера (Model Context Protocol) внутри zapret-gui: точка
  `POST /api/mcp`, реестр инструментов, разрешения и редактирование секретов.
  Использовать при любых задачах о: наших MCP-инструментах и их объявлении
  (декоратор `@tool`, scope/mutating, схема аргументов, форма ответа
  `content`+`structuredContent`+`isError`), реестре и автозагрузке
  `core/mcp/tools/*`, модели разрешений (12 переключателей
  `mcp.permissions`, зависимость `experiments` → `control`+`probes`,
  `self_edit_core` → `self_edit`, `secrets` без своих инструментов),
  границе записи настроек (whitelist
  поддеревьев, deny-поля, `is_writable`/`writable_paths`), маскировке
  секретов (`core/mcp/redact.py`, маска по ключам, а не по значениям,
  режим «без маскировки» по `raw: true` под разрешением `secrets`),
  ресурсах-справочниках (`core/mcp/resources.py`, схема `zapret://…`,
  живой `nfqws2 -?`, карта `--lua-desync`, каталоги, зеркало «ресурс =
  инструмент» через `docs_get`), описаниях настроек
  (`core/mcp/config_docs.py`, `config_describe`) и промтах-сценариях
  (`core/mcp/prompts.py`), read-only инструментах по nfqws2 (стратегии и
  каталоги, хостлисты и ipset'ы, blob'ы и функции `--lua-desync`, правила
  firewall, «дошёл ли трафик до движка»), сводке по туннельным движкам
  (`tunnels_status`, `core/tunnels_overview.py`: одна запись движка на все
  шесть, `traffic_source` вместо общего знаменателя), диагностике и границе
  «читает/пробует» (`diagnostics_run` без `probes` — только пассивная часть,
  `dpi_report` проб не запускает, `updates_check` по умолчанию из кеша),
  общей форме списка и пагинации
  (`core/mcp/tools/_paging.py`: `items`/`total`/`offset`/`limit`/
  `truncated`, ужимание окна под лимит ответа), записи настроек
  (`config_set` — дифф «было/стало», список заменяется целиком,
  `config_writable_paths`), журнале вызовов и откате
  (`core/mcp/audit.py`: `mcp-audit.jsonl` и `mcp-undo.json` рядом с
  `settings.json`, обобщённый снимок `{kind, target, before, after}`,
  `audit_list`, `mcp_undo_last`),
  активных пробах и тяжёлых прогонах (`core/probe_runner.py`:
  `probe_targets`/`probe_compare` и вердикты
  `bypass_helps`/`no_difference`/`target_down`/`bypass_hurts`/`unknown`,
  лимиты `mcp.probes`; асинхронный контракт `core/mcp/tools/_jobs.py` —
  `job_id`, опрос `*_status`, инкремент `*_output` по `offset`; сканер
  стратегий, blockcheck и blockcheck2, healthcheck и матрица
  связности),
  движке экспериментов (`core/strategy_experiment.py`: варианты
  `args`/`strategy_id`/`profiles`, baseline без обхода, медиана по
  повторам, `score` формулой сканера, `delta_vs_baseline`, хвост лога по
  окну варианта, правила-подсказки `HINT_RULES` данными, дедмен-свитч
  `ttl_sec` и снимок `.mcp-experiment.json` на диске,
  `strategy_experiment_*` под разрешением `experiments`),
  shell и системе (`core/shell_exec.py`: два режима — argv без оболочки
  и `sh -c` под `shell_full`, safe-список `SAFE_COMMANDS` данными,
  `DENY_RULES` с нормализацией команды, `CONFIRM_RULES` и одноразовый
  `confirm_token`, дедмен-свитч `guard`/`run_id` с файлом
  `mcp-shell-guards.json` и `recover_guards()`, фоновые задачи
  `shell_job_*`; `shell_exec`/`shell_exec_async`/`shell_confirm`,
  `file_read`/`file_list`/`file_write`, `package_list`/`_install`/
  `_remove`, `service_list`/`service_control`, `system_reboot` под
  `dangerous`; `permissions.IMPLIES` — `shell_full` открывает
  `shell_readonly`; `audit.note()` — итог вызова в журнале),
  сборке и проверке стратегий (`strategy_compose` — декларативные
  профили `filter`/`payload`/`desync` → argv тем же `build_nfqws_args`,
  что и UI; `strategy_validate` — `nfqws2 --intercept=0` по
  `strategy_id`/`args`/`profiles`; линтер `core/strategy_lint.py` —
  чистые функции, коды `unknown_lua_function`/`blob_unknown`/
  `blob_file_missing`/`blob_declared_after_new`/`lua_init_order`/
  `bare_trick_no_filter`/`l7_filter_without_ports`/`no_desync_action`/
  `engine_owned_option`, ошибка линтера делает ответ `isError`; сборщик
  вырезает из стратегии опции, которыми владеет GUI — `--user`/`--qnum`/
  `--fwmark`/`--pidfile`/`--writable`/`--debug=@файл`),
  транспорте и авторизации (Bearer-токен, Origin, bind, рейт-лимит,
  `/api/mcp/info`, белый список `Host` против DNS-rebinding —
  `core/host_guard.py` и `gui.allowed_hosts`), совместимости с живыми клиентами
  (legacy-SSE `GET /api/mcp/sse` + `POST /api/mcp/messages` под флагом
  `mcp.transports.sse`, сессии и их уборка в `core/mcp/session.py`,
  рассылка `notifications/tools/list_changed`; stdio-мост
  `core/mcp/stdio.py` и `zapret-gui mcp --stdio` через ssh; подкоманда
  `zapret-gui mcp status|tools|call|token|audit|code` в `core/cli.py`),
  странице «MCP-сервер» в веб-интерфейсе (`web/js/pages/mcp.js` и
  `api/mcp_ui.py`: `/api/mcp/ui/state` одним ответом, выдача токена и
  раздача разрешений без перезапуска, счётчик публикуемых
  инструментов, журнал и откат, кнопка «запретить shell немедленно»;
  поддерево `/api/mcp/ui/` исключено из врезки Bearer-токена в
  `app.py`; тексты предупреждений — `mcp.warn.*`/`mcp.risk.*` в
  `web/js/i18n/*`),
  запуске и правке туннелей (`core/tunnels_control.py`: одна форма на
  шесть движков, `tunnel_up`/`tunnel_down`/`tunnel_restart`,
  `tunnel_config_get`/`_save`, `subscription_refresh`, `pool_refresh`
  под `tunnels_write`), маршрутах единого слоя
  (`core/mcp/tools/routing.py`: `unified_route_list`/`_status` на
  чтение, `_save`/`_delete`/`_apply` под `tunnels_write`,
  `unified_reapply_all` под `dangerous`), правке lua на ходу
  (`lua_script_get`/`_patch`/`_delete`, `apply=true` →
  `nfqws_restart`), снифере трафика после движка
  (`core/traffic_capture.py` — фиксированный argv tcpdump, потолки
  `mcp.capture`, автоудаление файла; `core/pcap_reader.py` — разбор
  pcap в поля: флаги, TTL, длина, SNI), ожидании вместо опроса
  (`core/mcp/tools/jobs.py`: `job_wait`, бюджет `mcp.limits.wait_sec`,
  разрешение по виду операции), подписке на ресурсы и живом статусе
  (`resources/subscribe` + `notifications/resources/updated` поверх
  legacy-SSE и stdio-моста — там поток-писатель со своей сессией и
  замком на stdout, ресурс `zapret://state/jobs`, период опроса
  `ResourceSpec.poll` и отпечаток `resources.digest`), памяти подбора
  (`core/strategy_memory.py` — «домен → что сработало у этого
  провайдера», локальная метка сети, инструмент `strategy_memory` и
  ресурс `zapret://memory/strategies`), снифере внутри эксперимента
  (`capture=true` в `strategy_experiment_start`, сводка по окну
  варианта и подсказки по TTL/SNI), lua-дампе движка
  (`lua_capture=true`, `core/lua_capture.py`: `pcap` из
  `zapret-pcap.lua` перед первым приёмом профиля, `--writable` от
  сборщика, подсказка `lua_capture_empty`), экспорте находки в формат каталога
  (`core/catalog_export.py`, `strategy_export_catalog`, проверка
  round-trip нашим же парсером), встроенном агенте в GUI
  (`core/agent_runner.py` + `core/llm_client.py` + `api/agent.py` +
  `web/js/pages/agent.js`: клиент к OpenAI-совместимому API — LM
  Studio, Ollama, — цикл поверх `registry.call`, флаг `agent.enabled`,
  разрешения берутся у MCP), ошибках самого GUI (журнал падений
  `core/mcp/crashes.py` — трассировка и `crash_id` из `registry.call`;
  черновики issue `core/mcp/issues.py` — `issue_draft`/`issue_draft_list`,
  место в коде и repro от сервера, склейка повторов, маскировка доменов,
  ссылка `/issues/new` без токена на роутере, `zapret-gui mcp issues`),
  мини-валидаторе JSON Schema (`core/mcp/schema.py`),
  диспетчере JSON-RPC (`core/mcp/server.py`, ревизия спеки 2025-06-18,
  `initialize`/`tools/list`/`tools/call`, батч, уведомления), тестах-сторожах
  (`tests/test_mcp_*.py`: счётчик инструментов, утечка секретов, writable-пути,
  синхронность реестра с документацией — `tests/test_mcp_tools_docs.py`) и
  разделении документации (README — «зачем и как включить», этот скил —
  сигнатуры и грабли, `CoderManual.md` — куда класть новый инструмент,
  `docs/mcp/` — архив рабочих заданий).
  Источник истины по спеке — modelcontextprotocol.io (ревизия 2025-06-18),
  по нарезке работ — `docs/mcp/00-contract.md` и `docs/mcp/HANDOFF.md`,
  привязка — наш код `core/mcp/*.py`, `core/mcp/tools/*.py`, `api/mcp.py`.
---

# MCP-сервер zapret-gui — справочник

Слепок того, **как устроен MCP в этом репозитории**. Читать вместо того,
чтобы заново разбирать уже написанный код: контракт
(`docs/mcp/00-contract.md`) говорит, *что* строили, этот файл — *как оно
сделано сейчас*. Фича доведена до конца (S1–S18 и ревью после них); рабочие задания
сессий лежат в [`docs/mcp/`](../../../docs/mcp/README.md) как архив.

**Этот файл — для того, кто правит код.** Пользовательский текст («зачем
это нужно, как включить, чем рискую») живёт в README, раздел
«Управление через ИИ (MCP)», и дублировать его сюда не надо: разойдутся.
Здесь — точные сигнатуры, границы и грабли.

Добавили инструмент — обязаны появиться: строка в таблице ниже (имя,
scope, mutating, файл, аргументы), имя в README и число в
`tests/test_mcp_tool_counts.py`. Первые два стережёт
`tests/test_mcp_tools_docs.py`, и он сверяет не только наличие строки, но
и её scope с объявленным в коде.

Ревизия спеки: **2025-06-18** (`server.PROTOCOL_VERSION`; понимаются также
`2025-03-26` и `2024-11-05`). Ограничение на весь пакет — **только stdlib**.

## Карта кода

| Файл | Что в нём |
|---|---|
| `api/mcp.py` | HTTP: `POST /api/mcp`, `GET/DELETE` → 405, `GET /api/mcp/info`, legacy-SSE (`GET /api/mcp/sse`, `POST /api/mcp/messages`) |
| `core/mcp/server.py` | диспетчер JSON-RPC, методы протокола, псевдонимы реестра |
| `core/mcp/registry.py` | `@tool`, проверки объявления, автозагрузка, `call()`, `tool_result()` |
| `core/mcp/permissions.py` | 12 разрешений, зависимости, whitelist настроек на запись |
| `core/mcp/audit.py` | журнал вызовов (JSONL + ротация), снимки «до», диспетчер отката |
| `core/mcp/redact.py` | маскировка секретов (ключи, URL, сырой текст) |
| `core/mcp/schema.py` | мини-валидатор JSON Schema + `normalize_tool_schema()` |
| `core/mcp/auth.py` | bind → Origin → токен → рейт-лимит, `settings()`, `permissions()` |
| `core/mcp/resources.py` | ресурсы `zapret://…`, единая точка рендера |
| `core/mcp/config_docs.py` | описания настроек (данные, не код) |
| `core/mcp/prompts.py` | промты-сценарии |
| `core/mcp/crashes.py` | журнал падений инструментов: трассировка (кадры проекта), `crash_id`, отпечаток |
| `core/mcp/issues.py` | черновики issue: контекст, склейка повторов, маскировка доменов, markdown и ссылка `/issues/new` |
| `core/mcp/session.py` | сессии legacy-SSE: очередь ответов, живость потока, уборка мёртвых, рассылка `tools/list_changed` |
| `core/mcp/stdio.py` | stdio-мост: JSON-RPC построчно, локально или прокси в чужую точку; поток-писатель уведомлений (`_Notifier`) |
| `api/mcp_ui.py` | **не протокол, а панель**: `/api/mcp/ui/*` для страницы MCP — одно состояние и действия (токен, разрешения, откат, аварийный запрет shell) |
| `web/js/pages/mcp.js` | страница «MCP-сервер»: включение, токен, разрешения, сниппеты, журнал, эксперимент, самоправка, shell |
| `core/mcp/tools/*.py` | сами инструменты, по модулю на домен |
| `core/mcp/tools/_paging.py` | общая форма списка и окно под лимит ответа (реестр модули с `_` пропускает) |
| `core/mcp/tools/_jobs.py` | асинхронная задача: `job_id`, опрос после конца прогона, отказ второму старту (реестр модули с `_` пропускает) |
| `core/nfqws_control.py` | **не в пакете MCP**: старт/стоп/перезапуск/SIGHUP, применение и сброс стратегии, `running()`, `busy()` — одним кодом для UI, CLI и MCP |
| `core/probe_runner.py` | **не в пакете MCP**: пробы по списку целей, сравнение «с обходом и без», лимиты `mcp.probes` |
| `core/nfqws_session.py` | **не в пакете MCP**: общий мьютекс на nfqws2/firewall (`acquire`/`holder`), снимок состояния и возврат «как было» |
| `core/strategy_experiment.py` | **не в пакете MCP**: движок экспериментов — варианты, baseline, метрики, правила-подсказки, дедмен-свитч и снимок на диске |
| `core/shell_exec.py` | **не в пакете MCP**: исполнение команд — safe-список, запреты, подтверждения, дедмен-свитч, фоновые задачи |
| `core/tunnels_control.py` | **не в пакете MCP**: поднять/погасить/перезапустить туннель и переписать его конфиг — одной формой на все шесть движков (пара к `tunnels_overview`) |
| `core/traffic_capture.py` | **не в пакете MCP**: короткий дамп tcpdump с фиксированным argv, потолками и автоудалением файла |
| `core/pcap_reader.py` | **не в пакете MCP и без единой зависимости**: разбор pcap в поля (направление, флаги, TTL, длина, SNI) и общая сводка `summarize()` |
| `core/lua_capture.py` | **не в пакете MCP**: lua-дамп движка — `--writable` для стратегий с `pcap`, вставка `pcap` в профили argv, разбор и удаление дампов |
| `core/mcp/tools/jobs.py` | `job_wait` — ожидание конца долгой операции вместо опроса в цикле |
| `core/mcp/tools/memory.py` | `strategy_memory` — что уже срабатывало на домене в этой сети |
| `core/strategy_memory.py` | **не в пакете MCP**: память подбора — файл рядом с `settings.json`, метка сети, наблюдения «домен + argv + чем кончилось» |
| `core/catalog_export.py` | **не в пакете MCP и без I/O**: argv → секция `catalogs/*.txt` с проверкой round-trip |
| `core/agent_runner.py` | **не в пакете MCP**: встроенный агент — цикл «модель → инструмент → модель» поверх `registry.call` |
| `core/llm_client.py` | **не в пакете MCP**: клиент к OpenAI-совместимому API на `urllib` (`/chat/completions`, `/models`) |
| `api/agent.py`, `web/js/pages/agent.js` | страница «Агент»: настройки сервера модели, готовые задачи, транскрипт прогона |
| `core/mcp/tools/routing.py` | маршруты единого слоя: чтение, правка, переприменение |
| `core/code_editor.py` | **не в пакете MCP**: самоправка — границы, staging, слепок дерева, проверки, снимки, применение |
| `core/code_guard.py` | **не в пакете MCP и без единого нашего импорта**: сторож перезапуска, отдельный процесс, откат по health-check и по TTL |
| `core/cli.py` | **не в пакете MCP**: подкоманда `zapret-gui mcp …` — status/tools/call/token/audit/code и точка входа моста |

## Как объявляется инструмент

```python
from core.mcp.registry import tool

@tool(
    name="logs_tail",           # <домен>_<действие>, snake_case
    scope="read",               # "read" или одно из permissions.PERMISSIONS
    mutating=False,             # True — меняет состояние устройства
    title="Tail GUI log",
    description=("EN first, RU after the slash / английский и русский "
                 "одной строкой, ≤ 300 символов"),
    schema={"type": "object", "properties": {...},
            "additionalProperties": False},
)
def logs_tail(args: dict) -> dict:
    """Короткий docstring по-русски."""
    from core.log_buffer import get_log_buffer   # импорт — внутри!
    return {"ok": True, "items": [...], "count": 0}
```

Правила, которые проверяются **на импорте** (`registry.ToolError`):

- имя — snake_case, не занято;
- описание непустое и ≤ 300 символов (`registry.MAX_DESCRIPTION`);
- `scope` и `mutating` объявлены явно; `mutating=True` при `scope="read"` —
  ошибка (такой инструмент был бы доступен без разрешения);
- схема разбирается нашим валидатором: неизвестный `type`, `required` без
  такого `properties`, не-объект в `properties` — ошибка.

Модуль в `core/mcp/tools/` подхватывается **сам** (`pkgutil`), перечислять
его нигде не надо. Импорт ленивый — при первом обращении к реестру.

## Форма ответа

```json
{"content": [{"type": "text", "text": "<тот же JSON строкой>"}],
 "structuredContent": {"ok": true, "...": "..."},
 "isError": false}
```

- обработчик возвращает **обычный dict**; `ok` и `elapsed_ms` дописываются
  сами;
- **ошибка инструмента — не ошибка JSON-RPC**: `isError: true` + `error` +
  `hint`, коды `-32700…-32603` остаются про сам протокол;
- одинаковые поля при успехе и неуспехе; списки — `items` + `count` +
  `truncated`; «нет данных» — честный ответ и то, что есть рядом
  (`available`, `sources`);
- **сериализация ровно одна** — `registry.tool_result()`: там маскировка
  секретов и обрезка по `mcp.limits.response_kb` (вместо обрубка JSON
  отдаётся `{truncated: true, size_bytes, limit_bytes, hint}`).

## Разрешения

`settings.json → mcp.permissions`, все двенадцать по умолчанию
`false`; чтение переключателя не имеет и доступно всегда.

| Ключ | Что открывает | Зависит от |
|---|---|---|
| `control` | старт/стоп/перезапуск движков, применение стратегий | — |
| `strategies_write` | CRUD стратегий, hostlist'ов, ipset'ов, lua | — |
| `config_write` | запись в whitelisted-поддеревья настроек | — |
| `probes` | активные пробы (трафик с роутера), blockcheck, сканер | — |
| `experiments` | движок экспериментов | `control`, `probes` |
| `tunnels_write` | конфиги и запуск туннелей, подписки, пул, маршруты единого слоя | — |
| `dangerous` | бинарники, автозапуск, миграции, переприменение ВСЕЙ маршрутизации, ребут | — |
| `shell_readonly` | safe-команды, чтение файлов и каталогов | — |
| `shell_full` | произвольная команда от root, запись файлов, пакеты | открывает `shell_readonly` |
| `self_edit` | чтение и правка модулей GUI (13 инструментов `code_*`) | — |
| `self_edit_core` | правка защищённого ядра; **своих инструментов нет**, спрашивается по месту | `self_edit` |
| `secrets` | ответ без маскировки по явному `raw: true` + запись секретных листьев настроек; **своих инструментов нет** | — |
| `any_write` *(псевдо)* | не переключатель: открывается ЛЮБЫМ из `WRITE_PERMISSIONS`. Нужен одному `mcp_undo_last` | — |

**`secrets` не открывает инструментов и не входит в
`WRITE_PERMISSIONS` (S17).** Он ничего не меняет сам — он снимает две
границы с того, что уже открыто другими разрешениями: маскировку
ответа (по явному `raw: true`, см. «Секреты») и запрет на запись
листьев настроек, похожих на секрет (`is_writable(path,
secrets=True)`). Поэтому и в `WRITE_PERMISSIONS` его нет: с одним
`secrets` менять нечего, а значит `mcp_undo_last` публиковать не за
чем. Запрет на ключи-расположения (`DENY_KEY_RE`) им НЕ снимается: к
секретам он отношения не имеет.

**`IMPLIES` — обратная сторона `REQUIRES` (S12).** `shell_full`
включает `shell_readonly` сам: кому отдали произвольную команду от
root, тому `df -h` уже отдали. Без этого пользователь видел бы
включённый `shell_full` и половину невидимых инструментов (чтение
файлов, список пакетов, статус служб) — и читал бы это как поломку.
Порядок в `effective()` значим: сначала гасим невыполненные
зависимости, потом раздаём вложенные, иначе снятое зависимостью
разрешение успело бы открыть своё вложенное. В `describe()` у такого
разрешения появляется `implied_by`, у открывающего — `opens`.

Зависимость, которая не выполнена, **не игнорируется молча**:
`permissions.denial(scope, perms)` возвращает `error`, `requires`, `missing`
и `hint` — иначе пользователь видит включённый флаг и выключенные
инструменты. `/api/mcp/info` отдаёт и `permissions` (как стоят), и
`permissions_effective` (как действуют), и `permissions_info` (таблица для
UI), и `tools_by_scope`.

## Инструменты (обновлять каждой сессией)

| Имя | Scope | Mut. | Файл | Аргументы (`?` — необязательный) | Что делает |
|---|---|---|---|---|---|
| `system_status` | read | нет | `tools/status.py` | — | платформа, аптайм, память, какие движки подняты |
| `nfqws_status` | read | нет | `tools/status.py` | — | движок nfqws2: pid, аптайм, argv, код выхода |
| `config_get` | read | нет | `tools/config.py` | path?, depth? | настройки по точечному пути, с флагом `writable` |
| `logs_tail` | read | нет | `tools/logs.py` | source?, level?, search?, since?, limit? | хвост журнала: `source`, `level`, `search`, `since`, `limit` ≤ 200 |
| `docs_get` | read | нет | `tools/docs.py` | topic?, uri?, section?, offset?, limit? | любой ресурс `zapret://…` постранично: `uri`/`topic`, `section`, `offset`/`limit` |
| `config_describe` | read | нет | `tools/docs.py` | path?, query?, limit? | описание настройки: тип, дефолт, единица, что значит 0/пусто, writable |
| `strategy_list` | read | нет | `tools/strategies.py` | query?, protocol?, level?, source?, featured?, active_only?, offset?, limit? | стратегии (builtin+user) с `is_active`; фильтры protocol/level/source/featured/active_only |
| `strategy_get` | read | нет | `tools/strategies.py` | id? | одна стратегия целиком: профили, их args, `techniques`, blob'ы |
| `catalog_search` | read | нет | `tools/strategies.py` | query?, technique?, protocol?, level?, label?, offset?, limit? | поиск по INI-каталогам: `query`, `technique`, protocol, level, label |
| `nfqws_command_preview` | read | нет | `tools/strategies.py` | strategy_id? | итоговый argv стратегии — через `build_preview_command`, как при живом запуске |
| `strategy_state_list` | read | нет | `tools/strategies.py` | host?, group?, offset?, limit? | выученное circular'ом из `state.tsv`: host, `group`, номер, возраст |
| `hostlists_list` | read | нет | `tools/lists.py` | offset?, limit? | списки доменов: сколько записей, путь, есть ли файл |
| `hostlist_get` | read | нет | `tools/lists.py` | name, search?, offset?, limit? | окно одного списка + `search`; на 50 000 доменов отдаёт окно, не дамп |
| `ipsets_list` | read | нет | `tools/lists.py` | name?, search?, offset?, limit? | списки IP: перечень, с `name` — содержимое |
| `lists_list` | read | нет | `tools/lists.py` | id?, offset?, limit? | именованные списки единого слоя: домены и CIDR по списку |
| `blobs_list` | read | нет | `tools/lists.py` | query?, missing_only?, offset?, limit? | реестр blob'ов и **существует ли файл** (`missing_only`) |
| `lua_functions_list` | read | нет | `tools/lists.py` | name?, query?, needs_blob?, offset?, limit? | функции `--lua-desync` с этого устройства: параметры, `needs_blob` |
| `firewall_status` | read | нет | `tools/firewall.py` | rules?, offset?, limit? | правила NFQUEUE, бэкенд, `queue_numbers`, `conflicts` |
| `traffic_recent` | read | нет | `tools/traffic.py` | minutes?, domain?, source?, offset?, limit? | дошёл ли трафик до движка: домен/профиль/вердикт за N минут |
| `tunnels_status` | read | нет | `tools/tunnels.py` | engine?, logs?, running_only?, instances?, offset?, limit? | шесть движков одним ответом: установлен/запущен/конфиги/трафик/последняя ошибка |
| `diagnostics_run` | read | нет | `tools/diagnostics.py` | checks?, services?, offset?, limit? | окружение, конфликты, предпосылки; сетевые пробы — по разрешению `probes` |
| `dpi_report` | read | нет | `tools/diagnostics.py` | targets?, offset?, limit? | последняя классификация DPI из blockcheck; **проб не запускает** |
| `updates_check` | read | нет | `tools/updates.py` | refresh?, updates_only?, offset?, limit? | версии движков и обновления; по умолчанию из кеша, `refresh` — по `probes` |
| `config_writable_paths` | read | нет | `tools/config.py` | section?, search?, offset?, limit? | что можно менять: путь, тип, текущее значение, `enum` |
| `audit_list` | read | нет | `tools/audit.py` | tool?, status?, mutating_only?, offset?, limit? | последние вызовы MCP из журнала, новые первыми, с пометкой «ещё откатывается» |
| `job_wait` | read | нет | `tools/jobs.py` | kind, job_id?, timeout_sec? | ЖДАТЬ конца долгой операции одним вызовом; разрешение спрашивается по виду операции |
| `unified_route_list` | read | нет | `tools/routing.py` | id?, method?, search?, enabled_only?, offset?, limit? | маршруты единого слоя: назначение → метод, fallback'и, приоритет |
| `unified_route_status` | read | нет | `tools/routing.py` | id?, offset?, limit? | какой метод РАБОТАЕТ сейчас (`active_method`), статистика монитора, советы сканера |
| `strategy_memory` | read | нет | `tools/memory.py` | targets?, all_networks?, offset?, limit? | что уже срабатывало на домене В ЭТОЙ сети: argv, +удач/−неудач, давность |
| `issue_draft` | read | нет | `tools/issues.py` | title, kind?, tool?, component?, crash_id?, actual?, expected?, steps?, evidence?, args?, severity?, include_targets? | черновик issue об ошибке САМОГО GUI; место в коде, трассировку и repro сервер дописывает сам |
| `issue_draft_list` | read | нет | `tools/issues.py` | id?, status?, offset?, limit? | черновики (новые первыми) + падения без черновика; с `id` — текст и ссылка |
| `config_set` | config_write | **да** | `tools/config.py` | path, value | записать ОДНУ настройку; ответ — дифф «было/стало», список заменяется целиком |
| `nfqws_start` | control | **да** | `tools/nfqws.py` | — | правила перехвата + движок с активной стратегией; обратное — `nfqws_stop` |
| `nfqws_stop` | control | **да** | `tools/nfqws.py` | — | остановить движок и снять правила |
| `nfqws_restart` | control | **да** | `tools/nfqws.py` | — | перезапуск со свежесобранными аргументами активной стратегии |
| `nfqws_reload_lists` | control | **да** | `tools/nfqws.py` | reason? | SIGHUP: перечитать списки БЕЗ перезапуска; в ответе `signalled` |
| `strategy_apply` | control | **да** | `tools/nfqws.py` | id | применить стратегию по id; снимок вида `strategy_active` |
| `firewall_apply` | control | **да** | `tools/firewall.py` | — | поставить правила NFQUEUE; порты управления исключаются |
| `firewall_remove` | control | **да** | `tools/firewall.py` | — | снять правила: трафик пойдёт напрямую |
| `strategy_save` | strategies_write | **да** | `tools/strategies.py` | id, name, description?, protocol?, profiles | создать/перезаписать USER-стратегию; профили заменяются целиком; `validation` — прогон `--intercept=0` |
| `strategy_delete` | strategies_write | **да** | `tools/strategies.py` | id | удалить USER-стратегию; builtin — отказ |
| `hostlist_edit` | strategies_write | **да** | `tools/lists.py` | name, mode?, domains | `replace`/`add`/`remove` по списку доменов; SIGHUP; пустой список — предупреждение |
| `ipset_edit` | strategies_write | **да** | `tools/lists.py` | name, mode?, entries | то же для IP/CIDR; непринятые записи перечисляются |
| `blob_add` | strategies_write | **да** | `tools/lists.py` | name, hex | записать blob из hex (≤ 64 КБ); builtin-имена — отказ |
| `lua_script_save` | strategies_write | **да** | `tools/lists.py` | name, content, force? | сохранить lua-скрипт; битый синтаксис — отказ, `force=true` перебивает |
| `lua_script_get` | strategies_write | нет | `tools/lists.py` | name?, offset?, limit?, numbered? | текст скрипта окном; без имени — перечень скриптов с их функциями |
| `lua_script_patch` | strategies_write | **да** | `tools/lists.py` | name, edits?, diff?, force?, apply? | точечная правка (тем же кодом, что `code_patch`); `apply=true` — ещё и `nfqws_restart` |
| `lua_script_delete` | strategies_write | **да** | `tools/lists.py` | name | удалить пользовательский скрипт; bundled — отказ; в ответе — потерянные функции |
| `mcp_undo_last` | any_write | **да** | `tools/audit.py` | kind? | откатить последнее изменение по снимку с диска (любой вид) |
| `scan_status` | read | нет | `tools/scan.py` | job_id? | прогресс подбора: фаза, сколько проверено, `baseline_open`; `job_id` — опционально |
| `scan_results` | read | нет | `tools/scan.py` | failed?, offset?, limit? | что нашёл подбор, лучшие первыми; `failed=true` — что НЕ сработало |
| `blockcheck_status` | read | нет | `tools/blockcheck.py` | job_id? | прогресс НАШЕГО blockcheck; вердикт — в `dpi_report` |
| `blockcheck2_status` | read | нет | `tools/blockcheck.py` | job_id? | прогон скрипта bol-van: идёт ли, код выхода, `found`, `highlights` |
| `blockcheck2_output` | read | нет | `tools/blockcheck.py` | offset?, limit?, job_id? | телеметрия скрипта инкрементально: `offset` → `next_offset` |
| `healthcheck_status` | read | нет | `tools/blockcheck.py` | history?, limit? | расписание, сервисы, история и `fail_streak`; проб не запускает |
| `connectivity_matrix` | read | нет | `tools/probes.py` | refresh?, ifaces?, offset?, limit? | матрица «цель × интерфейс»; `refresh` — по `probes` |
| `probe_targets` | probes | нет | `tools/probes.py` | targets, repeats?, timeout_sec?, port?, offset?, limit? | проба доменов DNS→TCP→TLS→HTTP; коды из `PROBE_CODES`, состояния не меняет |
| `probe_compare` | probes | **да** | `tools/probes.py` | target, repeats?, timeout_sec?, toggle? | домен с обходом и без; вердикт из пяти; переключение движка требует ещё и `control` |
| `scan_start` | probes | **да** | `tools/scan.py` | target, protocol?, mode?, resume?, dpi_type? | запустить подбор стратегий; ответ — `job_id`, сразу |
| `scan_stop` | probes | **да** | `tools/scan.py` | — | остановить подбор; проверенное остаётся в `scan_results` |
| `blockcheck_start` | probes | **да** | `tools/blockcheck.py` | mode?, domains?, timeout_sec? | наш blockcheck в фоне; отчёт потом — `dpi_report` |
| `blockcheck2_start` | probes | **да** | `tools/blockcheck.py` | domains?, scanlevel?, ipv?, repeats?, http?, tls12?, tls13?, http3? | оригинальный скрипт zapret2 (DOMAINS/SCANLEVEL/REPEATS/…) |
| `blockcheck2_stop` | probes | **да** | `tools/blockcheck.py` | — | прибить скрипт; собранная телеметрия остаётся читаемой |
| `healthcheck_run` | probes | **да** | `tools/blockcheck.py` | — | разовый прогон healthcheck в фоне; результат — в `healthcheck_status` |
| `traffic_capture_start` | probes | **да** | `tools/traffic.py` | iface?, host?, port?, proto?, packets?, seconds? | короткий дамп после движка; argv фиксирован, ответ — `run_id`, сразу |
| `traffic_capture_status` | probes | нет | `tools/traffic.py` | run_id? | идёт ли дамп и сколько успел снять |
| `traffic_capture_result` | probes | нет | `tools/traffic.py` | run_id?, summary_only?, with_sni_only?, offset?, limit? | пакеты полями (флаги, TTL, длина, SNI) + сводка: разрезан ли ClientHello, разные ли TTL |
| `traffic_capture_stop` | probes | **да** | `tools/traffic.py` | — | прибить дамп; снятое остаётся читаемым |
| `scan_apply` | control | **да** | `tools/scan.py` | index?, strategy_id? | применить найденное: сохранить USER-стратегию и поднять движок; нужен ещё `strategies_write` |
| `strategy_experiment_start` | experiments | **да** | `tools/experiments.py` | variants, targets?, probes?, repeats?, baseline?, ttl_sec?, keep_best? | прогнать варианты стратегии с измерением; ответ — `run_id`, сразу |
| `strategy_experiment_status` | experiments | нет | `tools/experiments.py` | — | фаза, номер варианта, сколько осталось до авто-отката |
| `strategy_experiment_result` | experiments | нет | `tools/experiments.py` | run_id?, include_log?, offset?, limit? | отчёт: цифры по целям, `score`, дельта к baseline, лог движка, подсказки |
| `strategy_experiment_commit` | experiments | **да** | `tools/experiments.py` | label?, save_as?, save_name?, make_active? | оставить вариант применённым; `save_as` — ещё и `strategies_write` |
| `strategy_experiment_rollback` | experiments | **да** | `tools/experiments.py` | — | вернуть состояние к снимку немедленно |
| `strategy_experiment_stop` | experiments | **да** | `tools/experiments.py` | — | остановить прогон; измеренное остаётся в отчёте |
| `strategy_experiment_history` | experiments | нет | `tools/experiments.py` | offset?, limit? | прошлые прогоны этого процесса GUI, новые первыми |
| `strategy_compose` | strategies_write | нет | `tools/compose.py` | profiles, validate? | описание (фильтр/payload/инстансы) → argv + команда + линтер; ничего не сохраняет |
| `strategy_validate` | strategies_write | нет | `tools/compose.py` | strategy_id?, args?, profiles? | `nfqws2 --intercept=0` по `strategy_id`/`args`/`profiles`: опции, файлы и **исполнение lua-init** |
| `strategy_export_catalog` | strategies_write | нет | `tools/compose.py` | strategy_id?, args?, section_id?, name?, author?, label?, description?, protocol? | argv → секция `catalogs/*.txt`, проверенная нашим же парсером; файлов НЕ пишет |
| `tunnel_up` | tunnels_write | **да** | `tools/tunnels.py` | engine, name? | поднять инстанс движка (шесть движков — шесть способов, см. `core/tunnels_control.py`) |
| `tunnel_down` | tunnels_write | **да** | `tools/tunnels.py` | engine, name? | погасить инстанс; маршруты, которые вели в него, остаются |
| `tunnel_restart` | tunnels_write | **да** | `tools/tunnels.py` | engine, name? | перезапуск — так применяется правка конфига |
| `tunnel_config_get` | tunnels_write | нет | `tools/tunnels.py` | engine, name, raw? | текст конфига sing-box/mihomo/AWG; ключи замаскированы, если не `raw` |
| `tunnel_config_save` | tunnels_write | **да** | `tools/tunnels.py` | engine, name, text, restart? | переписать конфиг ЦЕЛИКОМ; проверка разбором самого движка; откат — `mcp_undo_last` |
| `subscription_refresh` | tunnels_write | **да** | `tools/tunnels.py` | id? | перекачать подписку (или все) и пересобрать её конфиг |
| `pool_refresh` | tunnels_write | **да** | `tools/tunnels.py` | status_only? | пересобрать пул серверов фоном; опрос — `job_wait(kind="pool")` |
| `unified_route_save` | tunnels_write | **да** | `tools/routing.py` | method, id?, name?, destination?, fallbacks?, devices?, enabled?, monitor_enabled?, failover_enabled?, probe_domain?, priority?, apply? | создать/заменить маршрут ЦЕЛИКОМ; непереданные поля берутся из прежней записи |
| `unified_route_delete` | tunnels_write | **да** | `tools/routing.py` | id | удалить маршрут и снять его с ядра |
| `unified_route_apply` | tunnels_write | **да** | `tools/routing.py` | id | разложить ОДИН маршрут заново (домены резолвятся заново) |
| `unified_reapply_all` | dangerous | **да** | `tools/routing.py` | — | sweep протухших `ip rule`/таблиц + переприменение ВСЕЙ маршрутизации |
| `shell_exec` | shell_readonly | **да** | `tools/shell.py` | command?, argv?, timeout_sec?, workdir?, guard? | команда на роутере; safe-список и argv — по `shell_readonly`, произвольная строка (`sh -c`) — по `shell_full` |
| `shell_exec_async` | shell_readonly | **да** | `tools/shell.py` | command?, argv?, timeout_sec?, workdir?, label?, guard? | то же фоном: ответ — `job_id`, сразу |
| `shell_job_status` | shell_readonly | нет | `tools/shell.py` | job_id? | состояние фоновой команды; без `job_id` — список всех |
| `shell_job_output` | shell_readonly | нет | `tools/shell.py` | job_id, offset? | вывод фоновой команды инкрементально: `offset` → `next_offset` |
| `shell_job_stop` | shell_readonly | **да** | `tools/shell.py` | job_id | прибить фоновую команду; собранный вывод остаётся читаемым |
| `shell_confirm` | shell_readonly | **да** | `tools/shell.py` | confirm_token?, run_id? | второй шаг: `confirm_token` — исполнить, `run_id` — снять дедмен |
| `file_read` | shell_readonly | нет | `tools/files.py` | path, offset?, limit_kb?, tail? | окно файла (`offset`/`limit_kb`/`tail`), секреты вырезаны |
| `file_list` | shell_readonly | нет | `tools/files.py` | path, search?, offset?, limit? | каталог полями: имя, размер, права, mtime, тип |
| `package_list` | shell_readonly | нет | `tools/packages.py` | search?, offset?, limit? | что установлено: `opkg list-installed` / `apk list -I` |
| `service_list` | shell_readonly | нет | `tools/services.py` | search?, offset?, limit? | исполняемые скрипты `/opt/etc/init.d` и `/etc/init.d` |
| `service_control` | shell_readonly | **да** | `tools/services.py` | name, action? | `status` — по `shell_readonly`, `start/stop/restart/reload` — по `shell_full` |
| `file_write` | shell_full | **да** | `tools/files.py` | path, content, mode?, create_dirs? | запись внутрь `allow_write_paths`, атомарно, с бэкапом в аудит |
| `package_install` | shell_full | **да** | `tools/packages.py` | name, update? | поставить пакет; обратимо через `mcp_undo_last` |
| `package_remove` | shell_full | **да** | `tools/packages.py` | name | удалить пакет — через `shell_confirm`; обратимо |
| `system_reboot` | dangerous | **да** | `tools/system.py` | reason? | перезагрузка: токен → `shell_confirm` → `core/system_control.py` |
| `code_tree` | self_edit | нет | `tools/code.py` | mask?, path?, offset?, limit? | файлы GUI: путь, размер, mtime, `protected`, `staged`; маска и пагинация |
| `code_read` | self_edit | нет | `tools/code.py` | path, offset?, limit?, numbered? | окно файла: `content` (для точного совпадения) + нумерация по запросу |
| `code_search` | self_edit | нет | `tools/code.py` | pattern, regex?, path?, mask?, context?, limit?, offset? | поиск по коду (подстрока/регэксп) с контекстом ±N строк |
| `code_check` | self_edit | нет | `tools/code.py` | paths?, lint?, tests?, test_pattern? | проверки **без применения**: разбор, импорт из слепка, полный `make lint` |
| `code_test` | self_edit | нет | `tools/code.py` | pattern?, timeout_sec? | `pytest tests/ -q -k …` по staging-слепку; нет pytest — `available: false` |
| `code_history` | self_edit | нет | `tools/code.py` | offset?, limit? | снимки: id, время, файлы, размер diff, состояние, причина отката |
| `code_diff` | self_edit | нет | `tools/code.py` | against?, snapshot_id?, path?, limit_kb? | unified diff: staging / снимок / исходный эталон |
| `code_export_patch` | self_edit | нет | `tools/code.py` | limit_kb? | все локальные правки устройства одним диффом — чтобы перенести в репозиторий |
| `code_patch` | self_edit | **да** | `tools/code.py` | path?, edits?, diff?, drop? | точечная правка в staging: `edits` ИЛИ `diff`; неоднозначное совпадение — отказ |
| `code_write` | self_edit | **да** | `tools/code.py` | path, content, mode? | файл целиком (в т.ч. новый) — тоже в staging |
| `code_apply` | self_edit | **да** | `tools/code.py` | reason, restart?, run_tests?, test_pattern? | снимок → проверки → диск → сторож → перезапуск; **рвёт соединение** |
| `code_commit` | self_edit | **да** | `tools/code.py` | snapshot_id? | подтвердить применённое; без него откат по `commit_ttl_sec` |
| `code_rollback` | self_edit | **да** | `tools/code.py` | snapshot_id?, restart?, reason? | вернуть снимок (последний или по `snapshot_id`) |
Эталон формы — первые четыре: одинаковые имена полей, одинаковая
обработка «нет данных», одинаковые лимиты. Новый инструмент делается по ним.
`docs_get`/`config_describe` — эталон **постраничного** ответа
(`offset`/`limit`/`truncated`/`next_offset`).

### Списки: одна форма на всех (`tools/_paging.py`)

Модуль с подчёркиванием — реестр такие пропускает. Через него проходит
**каждый** список, и он же задаёт контракт:

| Поле | Что значит |
|---|---|
| `items` | окно записей |
| `total` | сколько подошло под фильтр **всего**, а не сколько отдано |
| `count` | сколько в `items` |
| `offset` / `limit` | какое окно отдано |
| `truncated` | есть ли что-то за окном; при `true` — ещё и `next_offset` |

`page()` **меряет собранный ответ и ужимает окно под
`mcp.limits.response_kb`** (`shrunk_to_fit`, `requested_limit`): ответ сверх
лимита реестр заменяет ЦЕЛИКОМ на «слишком много», и модель получает не
страницу данных, а сообщение об ошибке. `empty(reason, hint)` — пустой
список с объяснением; `unavailable(what, reason, hint)` — честное «этого на
устройстве нет» при `ok: true`.

### Что добавлено в `core/*.py` ради этих инструментов

Логика в менеджерах, а не в `tools/*` — поэтому доступна и UI, и CLI:

| Где | Что | Зачем |
|---|---|---|
| `models.CatalogEntry.desync_names()` | имена функций `--lua-desync` записи | «приём» стратегии; по ним же ищет `catalog_search` |
| `catalog_loader.CatalogManager.find_entries()` | фильтры + окно + `total` | `search_entries` не умеет ни уровень, ни приём, ни окно |
| `blob_registry.list_blobs()` | весь реестр + `exists` файла | нет файла = ПУСТОЙ fake, «тихий 0%» |
| `firewall.get_conflicts()` / `queue_numbers()` | расхождения правил, движка и конфига | три разные поломки выглядят снаружи одинаково |
| `nfqws_manager.resolve_binary()` | путь к бинарю с откатом на дефолт | `cfg.get()` отдавал `None`, и argv собирался с `None` в нулевом элементе |
| `core/traffic_recent.py` | три источника «видел ли движок трафик» | «настроен ли домен» ≠ «дошёл ли пакет» |
| `strategy_scanner.compose_score()` / `credit_success()` | формула ранжирования и правило «baseline открыт — кредита нет» | одна формула на сканер и эксперименты: иначе «лучший вариант» и «лучшая стратегия в UI» — разные строки |
| `probe_runner.fold(..., latency="median")` | медиана вместо среднего | выброс по латентности на роутере — норма, и среднее из трёх замеров он переставляет местами |
| `core/tunnels_overview.py` | сводка по шести движкам в одной форме | шесть менеджеров отвечают о себе шестью способами |
| `tunnel_monitor.iface_counters()` | RX/TX интерфейса из `/sys/class/net` | счётчики нужны не только графикам |
| `diagnostics.check_services()` | обход сервисов с бюджетом времени | полный прогон уходит за любой таймаут вызова |
| `permissions.granted(name)` | «разрешение включено ПРЯМО СЕЙЧАС» | обработчику карта разрешений не передаётся |
| `core/probe_runner.py` | пробы по списку целей, сравнение «с обходом и без», лимиты | S10 берёт baseline оттуда же, а не пишет свои пробы |
| `nfqws_control.running()` | «движок поднят прямо сейчас» без побочных действий | сравнению нужно исходное состояние, а менеджер в тестах подменён в `_managers()` |
| `nfqws_control._is_running()` | `is_running` как метод ИЛИ как property | наш blockcheck иначе никогда не считался занявшим движок |
| `core/nfqws_session.py` | общий мьютекс на движок + снимок/восстановление | сканер и эксперимент иначе независимо «вернут как было», и победит второй |

### Туннели: одна запись движка на все шесть (S5)

Сводка собирается в `core/tunnels_overview.py` (не в `tools/`), поэтому
ею пользуются и MCP, и UI, и CLI. `overview(engine="", logs=True)` отдаёт
`engines` — список записей **одинаковой формы**, на неё будут опираться
S7 (запуск туннелей) и S15 (страница MCP):

| Поле записи движка | Что значит |
|---|---|
| `engine` / `title` | ключ (`singbox`, `mihomo`, `awg`, `usque`, `tgproxy`, `opera`) и человеческое имя |
| `installed` / `running` | есть ли бинарник; поднят ли хоть один инстанс |
| `version` / `binary` | что установлено и откуда запускается |
| `instances` | конфиги, интерфейсы или подпроцессы движка |
| `instances_count` / `running_count` | сколько их всего и сколько живых |
| `reason` | **почему** не установлен / не запущен — словами |
| `error` | движок не удалось опросить (и это не роняет остальных) |

Запись инстанса: `name`, `running`, `pid`, `iface`, `config`, `traffic`,
`traffic_source`, `last_error` + свои поля движка (`link_up` у usque,
`peers`/`last_handshake` у AWG, `redirect_active` у mtproto).

**Трафик не приводится к общему знаменателю.** У TUN-интерфейсов байты
лежат в `/sys/class/net` (`tunnel_monitor.iface_counters()`), у AWG их
отдаёт `awg show` по пирам, у нативного Keenetic-WG — NDMS, у
Telegram- и Opera-прокси интерфейса нет вовсе. Поэтому рядом с числом
всегда стоит `traffic_source`, а без честного источника — `traffic:
null`. Ноль здесь читался бы как «трафика не было».

**Движок не установлен — это ответ, а не ошибка** (`installed: false` +
`reason`), и `ok` остаётся `true`. Сломанный движок отвечает полем
`error` в своей записи: опрос каждого идёт под собственным `try`.

**Список конфигов подрезается внутри движка** (`instances`, по умолчанию
10, поле `instances_truncated`). Иначе два десятка конфигов sing-box
съедают лимит ответа, и `page()` выкидывает остальные пять движков —
ровно то, за чем инструмент и звали.

### Граница «читает / пробует» (S5, повторяет S8)

Выпустить трафик — не то же самое, что прочитать состояние (§4
контракта). Но инструмент, у которого пробует лишь **часть** действий,
не прячется целиком: пассивная половина не выпускает ни одного пакета и
объясняет половину жалоб.

Приём: инструмент публикуется в read-наборе всегда, а разрешение
спрашивается **за действие** — `permissions.granted("probes")`. В ответе
это видно:

```json
{"checks_run": ["environment", "conflicts", "prerequisites"],
 "checks_skipped": [{"check": "services", "permission": "probes",
                     "reason": "...", "hint": "включите разрешение ..."}],
 "probes": {"allowed": false, "permission": "probes", "hint": "..."}}
```

Так устроены `diagnostics_run` (сетевые пробы) и `updates_check`
(поход в апстрим; без разрешения — кеш и честное «чего не хватило», а
не отказ). `dpi_report` проб не запускает вовсе: он читает ПОСЛЕДНИЙ
сохранённый отчёт blockcheck, запуск — инструмент S8.

**`permissions.granted(name)`, а не `allowed(name)`.** Обработчику
карта разрешений не передаётся (см. `registry.call`), а `allowed()` без
явных `perms` видит пустую карту, то есть «ничего не разрешено».
`granted()` спрашивает конфиг и учитывает зависимости.

**Долгую пробу режет бюджет, а не таймаут.** `diagnostics.check_services
(names, deadline_sec)` останавливает обход, когда бюджет (по умолчанию
половина `mcp.limits.tool_timeout_sec`) исчерпан, и **перечисляет
пропущенные поимённо**: молча недосчитанный сервис читается как
«проверил, всё хорошо».

## Ресурсы, справочники и промты (S3)

URI-схема `zapret://…`, единственная точка рендера —
`resources.render(uri)`. Её зовут **и** `resources/read`, **и**
инструмент `docs_get`: содержимое совпадает по построению, а не по
договорённости (сторож — `tests/test_mcp_resources_mirror.py`).

| URI | `topic` | Что внутри |
|---|---|---|
| `zapret://docs/overview` | `overview` | что за сервер, что открыто разрешениями, с чего начинать |
| `zapret://skills/nfqws2` | `nfqws2`, `skill` | скил nfqws2 с диска (~90 КБ), по разделам `?section=12` |
| `zapret://nfqws2/cli` | `cli` | **живой** `nfqws2 -?` (`NFQWSManager.get_help()`) |
| `zapret://nfqws2/lua` | `lua` | карта `--lua-desync` (`LuaManager.desync_functions()`) |
| `zapret://catalogs` | `catalogs` | список каталогов и их размеры |
| `zapret://catalogs/<уровень>/<proto>` | — | сами стратегии каталога |
| `zapret://state/current` | `state` | что запущено сейчас (JSON, **живой** — см. `resources.VOLATILE`) |
| `zapret://state/jobs` | `jobs` | живой прогресс долгих операций (JSON, **живой**); ради него сделана подписка |
| `zapret://memory/strategies` | `memory` | что уже срабатывало на домене в ЭТОЙ сети |
| `zapret://config/describe` | `config` | описания настроек |

**Зачем зеркало.** LM Studio и OpenAI-совместимые мосты показывают
ресурсы пользователю, а не модели: справка, доступная только ресурсом,
моделью никогда не читается — а непрочитанная справка означает
придуманные флаги.

**Новый ресурс** — запись в `resources._specs()` + функция-рендерер,
возвращающая `{"text": …}` и, при желании, свои поля. Всё остальное
(редактирование секретов, `mime_type`, `params`) делает `_finish()`.
Ресурс обязан быть в `TOPICS` — иначе он доступен только тому, кто
помнит схему URI. У нового ресурса есть ещё и **период опроса**
(`ResourceSpec.poll`) — сколько стоит заглянуть в него при подписке
(S18); по умолчанию 120 с, и это правильный выбор для всего, что читает
файл или запускает бинарник.

**Пагинация.** `docs_get` режет текст по `_page_budget()` —
`mcp.limits.response_kb // 3` символов (кириллица в UTF-8 — два байта,
плюс экранирование). Ответ сверх лимита режется целиком
(`registry._truncated`), и модель получает не страницу, а «слишком
много».

**«Нет данных» против «нет такого».** Рендерер возвращает
`available: False` для честного «на устройстве нет» (бинарник, скил) —
это `ok: true`. Для «ты попросил то, чего нет» (раздел 99, каталог
`basic/nope`) — `found: False` + `error` + `hint`, и `docs_get` делает
из этого `isError`.

**Описания настроек** — `core/mcp/config_docs.py`, словарь
`путь → {text, unit, empty, see}`. Тип, дефолт и текущее значение туда
**не пишутся**: их даёт `resources.describe_path()` живьём из
`DEFAULT_CONFIG`/`ConfigManager`. Все writable-пути обязаны быть
описаны (сторож). Нет описания — `config_describe` так и отвечает и
показывает документированные рядом. S6 будет ссылаться на этот словарь
в отказах `config_set`.

**Промты** (`core/mcp/prompts.py`): `strategy_for_domain`,
`why_domain_blocked`, `router_health`. Имена инструментов **не зашиты
в текст**: шаг объявляет имя, рендер спрашивает реестр и помечает
отсутствующий «инструмента пока нет». Промт, обещающий модели
несуществующий инструмент, хуже отсутствующего.

## Запись настроек: где проходит граница

Граница — по **обратимости**, а не по чувствительности. Открыты поддеревья
`nfqws`, `filter`, `strategy`, `blockcheck`, `healthcheck`, `scan`,
`block_detector`, `dns_routing`, `logging` — и только **листья** (секцию
целиком записать нельзя).

Запреты сильнее разрешений:

- `nfqws.queue_num`, `nfqws.user`, `nfqws.desync_mark*`, `firewall.type` —
  на них держится перехват и собственный трафик GUI;
- `gui.*` — можно потерять способ отменить изменение; `mcp.*` — модель не
  расширяет собственные права;
- любые **расположения** файлов и каталогов (`*_path`, `*_dir`, `*_binary`,
  `logging.file_path`…): неверный путь не ломает громко, а тихо выключает
  часть логики. Отклоняем расположение, но не содержимое — списки и lua
  модель правит через `strategies_write`;
- всё, что похоже на секрет (тот же `redact.SECRET_KEY_RE`).

API: `permissions.is_writable(path)`, `permissions.why_not_writable(path)`,
`permissions.writable_paths()` (путь, тип, значение, `enum`),
`permissions.non_writable_paths()`. Запись (`config_set`) **обязана**
спрашивать `is_writable()` и ничего не решать сама.

**Настройки, которой нет в `DEFAULT_CONFIG`, не существует.** `is_writable`
требует, чтобы путь был в дефолтах: иначе `nfqws.nope.deep` выглядит листом
внутри разрешённой секции и завёл бы в `settings.json` ключ, который никто
не читает. Сюда же попадают `..`-подобные трюки — после `split_path` они
превращаются в несуществующий путь.

### Как устроен `config_set` (S6)

| Шаг | Что делает |
|---|---|
| граница | `is_writable()` → отказ зовёт `why_not_writable()` **и** `resources.describe_path()` |
| тип | сверяется со значением из `DEFAULT_CONFIG` (`bool` не пролезает как `integer`) |
| `enum` | `permissions.ENUMS` — если путь там есть |
| размер | `MAX_VALUE_BYTES` (32 КБ): списки доменов живут в hostlist'ах, а не в настройках |
| запись | только через `ConfigManager` (`set` + `save`); не сохранилось — живой конфиг возвращается как был |
| снимок | `audit.snapshot(KIND_CONFIG, path, before, after)` — после удачной записи |
| «вживую» | `logging.*` применяется тем же вызовом, что и `PUT /api/config` |

Ответ — **дифф**: `before`, `after`, `changed`, `saved`, `undo`. Значение,
совпавшее с текущим, не пишется и снимка не делает (`changed: false`).

**Список заменяется целиком, и сказано это трижды**: в описании
инструмента (модель читает его ДО вызова), в `hint` ответа и прежним
значением в `before` — целиком, чтобы список можно было собрать обратно без
второго вызова. Это единственное место, где формулировка описания важнее
кода: «добавь домен в healthcheck.services» иначе стирает остальные.

## Журнал и откат (S6)

`core/mcp/audit.py`, два файла рядом с `settings.json`
(`platform_dirs.config_dir()`, **не `/tmp`** — там tmpfs):

| Файл | Что в нём |
|---|---|
| `mcp-audit.jsonl` | строка на `tools/call`, ротация по `mcp.audit.keep` |
| `mcp-undo.json` | последние `SNAPSHOT_KEEP` снимков, закреплённые |

Разные файлы — не случайность: **ротация журнала не может унести снимок,
нужный `mcp_undo_last`**.

Пишет журнал **реестр**, а не инструменты: `registry.call` зовёт
`audit.begin(name)` перед обработчиком и `audit.record(...)` после — на
любом исходе, включая отклонённый вызов (`denied`), непрошедшие схему
аргументы (`invalid`), неизвестное имя (`unknown`) и упавший обработчик
(`error`). Уровень строки в лог-буфере: `denied`/`invalid`/`unknown` —
**warning**, `error` — error, удачная мутация — info, чтение — debug.

Инструменту остаётся одна строка:

```python
audit.snapshot(audit.KIND_CONFIG, path, before, after)   # ПОСЛЕ записи
```

Снимок обобщённый — `{kind, target, before, after}`, и это не «настройки,
оформленные универсально»: S7 положит туда стратегии и списки, S12 — файлы,
S13 — правки кода. Как откатывать свой вид, объявляет тот, кто снимок
делает:

```python
audit.register_undo(audit.KIND_CONFIG, _undo_config)     # на импорте модуля
```

`mcp_undo_last` берёт **последний неоткаченный** снимок (можно сузить
аргументом `kind`), зовёт обработчик и помечает снимок откаченным — второй
вызов не «переоткатывает» назад, а честно говорит «нечего». Пачка правок
откатывается по одной, от новой к старой.

**Что в журнал не попадает.** Токен — никогда. Аргументы пишутся после
`redact.redact()` **и** `redact.redact_text()`: имена наших аргументов
рабочие (`path`, `value`, `search`), и `token=…` внутри строки прошёл бы
маскировку по ключу насквозь.

**Как тесты подменяют пути.** Каталог берётся из
`platform_dirs.config_dir()`, а он смотрит на `ZAPRET_GUI_CONFIG_DIR` —
тест ставит переменную на временный каталог и подменяет там же
`config_manager._config_manager`. Проверка «переживает перезапуск» честная:
файл читает **другой интерпретатор** (`subprocess`).

## Управление и правка обхода (S7)

### Логика — в `core/nfqws_control.py`, а не в `tools/`

«Запустить обход» — это не `NFQWSManager.start()`: это правила firewall
до старта, пересборка аргументов активной стратегии, снятие правил при
неудаче и запись выбранной стратегии в конфиг. Последовательность жила
в `api/control.py` и `api/strategies.py`, то есть была доступна только
веб-интерфейсу; S7 перенёс её в `core/nfqws_control.py`, а роуты сделал
тонкими. Форма ответа у всех функций одна:

```python
{"ok": bool, "error": str, "nfqws": <NFQWSManager.get_status()>,
 "firewall": <FirewallManager.get_status()>, ...}
```

| Функция | Что делает |
|---|---|
| `start(strategy_args=None)` | правила → движок; `None` = пересобрать активную стратегию; неудача старта СНИМАЕТ поставленные правила |
| `stop()` | движок → снять правила (правила снимаются даже при неудачной остановке) |
| `restart(strategy_args=None)` | перезапуск + переприменение правил |
| `apply_strategy(id)` | собрать argv → правила → (пере)запуск → конфиг → автозапуск; в ответе `strategy`, `strategy_args`, `previous_id`, `error_code` |
| `clear_strategy()` | забыть применённую стратегию и остановить движок (нужна откату) |
| `reload_lists(reason)` | SIGHUP через `core/nfqws_reload` |
| `busy()` | кто держит движок прямо сейчас |

**`previous_id` возвращает сама `apply_strategy`.** Прочитать прежний
`strategy.current_id` у вызывающего уже нельзя — к этому моменту в
конфиге стоит новый.

**`error_code` вместо разбора текста.** `not_found` / `no_profiles` /
`start_failed`: по формулировке ошибки эти случаи не различить, а
реакция на них разная (и у модели, и у HTTP-роута, который отдаёт по
ним 404/400/500).

### Конкуренция за движок: общий мьютекс (S9)

Сканер стратегий, сравнение проб, будущий движок экспериментов и кнопки
«Старт»/«Стоп» хотят один и тот же nfqws2. Каждый умеет вернуть «как
было» — и в этом вся беда: два независимых восстановления дерутся,
побеждает закончивший вторым, роутер остаётся с чужой стратегией.
Поэтому право трогать движок выдаёт **`core/nfqws_session.py`**.

```python
from core.nfqws_session import OWNER_EXPERIMENT, get_nfqws_session

session = get_nfqws_session()                      # синглтон
with session.acquire(owner=OWNER_EXPERIMENT, timeout=0, reason="A/B"):
    snapshot = session.snapshot()                  # стратегия + движок + firewall
    try:
        session.apply_temporary(argv)              # только под захватом
    finally:
        session.restore(snapshot)                  # идемпотентно
```

| Метод | Что делает |
|---|---|
| `acquire(owner, timeout=0, reason="")` | контекст «движок наш»; занято — `SessionBusy` |
| `claim(...)` → `_Hold` | то же без `with` (захват и освобождение в разных функциях); `release()` идемпотентен |
| `holder()` | `{owner, reason, since, held_sec, pid, text}` или `{}` — читает и ЧУЖОЙ процесс |
| `held_by_me()` | держит ли сессию текущий поток |
| `snapshot(source=…)` | `nfqws_running/nfqws_args/nfqws_pid`, `firewall_applied/type/rules_count`, `strategy_id/strategy_name` |
| `restore(snapshot, source=…)` | вернуть как было; `{ok, error, changed[]}` |
| `apply_temporary(argv, source=…)` | поднять движок с чужими argv — **требует захвата** |

Владельцы: `OWNER_SCANNER` (`"scanner"`), `OWNER_EXPERIMENT`,
`OWNER_BLOCKCHECK`, `OWNER_PROBE`, `OWNER_UI`. Имя владельца и
`OWNER_TEXT` дают человеческий текст отказа («подбор стратегий
(scanner), уже 42 с: подбор для ya.ru»).

**`timeout=0` — «не ждать», а не «ждать вечно».** Модели нужен ответ, а
не зависший вызов.

**Захват вложенный (как `RLock`).** Держатель вправе звать
`core/nfqws_control` — тот берёт ту же сессию, и второй захват тем же
потоком проходит насквозь. Из другого потока/процесса — отказ.

**Блокировка процессная.** Внутри процесса — `threading`, между
процессами — `.nfqws-session.lock` рядом с `settings.json` (не в
`/tmp`: на роутере он чистится). Лок мёртвого процесса, лок старше
`STALE_SEC` (6 ч) и собственный остаток крадутся — упавший процесс не
запирает движок навсегда. Каталога нет или ФС только на чтение —
работаем одной внутрипроцессной блокировкой: отказать в запуске обхода
хуже.

**Где мьютекс берётся.** `core/nfqws_control`: `start`/`stop`/`restart`/
`apply_strategy`/`clear_strategy` (декоратор `_guarded`, владелец из
`source`); `strategy_scanner._run_scan` — на весь прогон;
`probe_runner.compare` — на «переключил → измерил → вернул» целиком.
`reload_lists` (SIGHUP) мьютекс НЕ берёт: он не меняет ни аргументы, ни
состояние процесса.

**Отказ выглядит одинаково.** `busy()` (вопрос ДО вызова) и сам
`nfqws_control` (отказ мьютекса) кладут в ответ одно и то же поле
`busy` с именем владельца; у результата `nfqws_control` вдобавок
`error_code="busy"`, а `_engine_result` переносит это в ответ
инструмента. Искать такой отказ в логах nfqws2 бесполезно — там ничего
не происходило.

**`busy()` спрашивает сессию, а не сканер.** Своя же блокировка
занятостью не считается (`held_by_me()` → `{}`), иначе держатель
сессии не смог бы позвать ни одну функцию `nfqws_control`. Запасной
путь (`_legacy_busy()`) остался для держателей, которые мьютекс пока не
берут: **blockcheck** управляет движком из своего скрипта, а
`scanner.apply_strategy(index)` (применение найденного ПОСЛЕ скана)
ходит в менеджеры сам.

И прежнее: «не смог спросить» — это не «занято». На устройстве без
сканера `get_strategy_scanner()` падает сама; считать это занятостью
значило бы сделать обход незапускаемым (есть тест-сторож).

### Порты управления: исключение живёт в `core/firewall.py`

`firewall.strip_management_ports(spec, cfg)` → `(spec, removed)`, список
защищённых даёт `management_ports(cfg)`: SSH (22), telnet/Entware-SSH
Keenetic (23, 233) и **порт GUI живьём из конфига**. Диапазон, задевший
защищённый порт, режется по нему, а не выбрасывается целиком
(`1:65535` → `1:21,24:232,234:8079,8081:65535`).

Проверка стоит **внутри `FirewallManager.apply_rules()`**, а не в
обёртке MCP, и это принципиально: `nfqws.ports_tcp` открыт на запись
через `config_set`, и связка «`config_set(ports_tcp="22,80,443")` →
`nfqws_start`» обошла бы защиту, стоящую только в `firewall_apply`.
Не осталось ни одного порта — правила **не применяются вовсе**
(`apply_rules` возвращает `False`): пустая спецификация уехала бы
дальше и подставилась из конфига.

### Снимки и откат: шесть видов вместо одного

| Вид (`audit.KIND_*`) | Кто кладёт | Что в `before` | Как откатывается |
|---|---|---|---|
| `config` | `config_set` | значение настройки | записать обратно |
| `strategy` | `strategy_save`, `strategy_delete` | стратегия целиком или `None` | сохранить обратно / удалить созданную |
| `strategy_active` | `strategy_apply` | прежний `current_id` или `None` | применить прежнюю / `clear_strategy()` |
| `hostlist`, `ipset` | `hostlist_edit`, `ipset_edit` | **весь** список | записать обратно |
| `blob` | `blob_add` | прежний hex или `None` | записать / удалить |
| `lua` | `lua_script_save` | прежний текст или `None` | записать / удалить |
| `firewall` | `firewall_apply/remove` | `{applied, rules_count, backend}` | поставить / снять |

**`mcp_undo_last` больше не под `config_write`.** Его scope —
псевдо-значение `permissions.ANY_WRITE_SCOPE` (`any_write`): он
публикуется при ЛЮБОМ из `permissions.WRITE_PERMISSIONS`. Модель с
`strategies_write` без `config_write` иначе получила бы право менять
стратегии без права их вернуть — прямое нарушение §5.4 контракта.
`probes` в `WRITE_PERMISSIONS` не входит: проба выпускает трафик, но
снимка не оставляет.

**У старта и остановки снимка нет намеренно.** «Было запущено» — это не
значение, которое можно вернуть снимком, а состояние процесса. Обратная
операция — соседний инструмент, и она названа в ответе полем `reverse`.

### Правка списков: три режима и одна ловушка

`replace` / `add` / `remove`. **`replace` затирает список целиком**, и
сказано это трижды: в описании инструмента (модель читает его ДО
вызова), в `hint` ответа и прежним содержимым в `before` — целиком,
чтобы список можно было собрать обратно без второго вызова. Ровно та же
формулировка, что у списков в `config_set`.

Ещё три вещи, которые ответ обязан сказать:

- **пустой hostlist — это выключенный фильтр** (`warning`): профиль с
  `--hostlist` перестаёт применяться к чему бы то ни было, а снаружи это
  выглядит как «ничего не изменилось»;
- **дошёл ли SIGHUP** (`reloaded`): менеджеры шлют его сами при каждой
  записи, но живого движка может не быть — правка, не дошедшая до
  процесса, читается как «добавил домен, а он всё равно не работает»;
- **что не принято** (`rejected`): «прислал десять доменов, прибавилось
  три» без списка отвергнутых выглядит как сбой.

### Имена файлов проверяются ДО менеджера

`StrategyManager.save_user_strategy` санитизирует id, заменяя
недопустимые символы на `_`: `../../etc/passwd` превратился бы в
существующий файл со странным именем вместо отказа. Поэтому у
`strategy_save`/`strategy_delete` свой `ID_RE`, у списков — `NAME_RE`
и `LUA_NAME_RE` (там дополнительно разрешена точка), и отказ объясняет,
что именно разрешено.

**Длину имени режет схема, а не обработчик.** `maxLength` в объявлении
инструмента — это ошибка протокола (`-32602`), до кода она не доходит;
тест на «слишком длинный id» обязан ждать `SchemaError`, а не `isError`.

### `strategy_save`: валидация есть, но не блокирует

После записи гоняется `NFQWSManager.dry_run()` (`nfqws2 --intercept=0`)
и кладётся в поле `validation`. Она **не мешает сохранению**: модели
нужна возможность сохранить черновик и починить его следующим вызовом.
Полная валидация — `strategy_validate` из S11, дублировать её здесь не
надо. Бинарника может не быть вовсе — тогда честное `available: false`.

У `lua_script_save` наоборот: **битый синтаксис — отказ** (`force=true`
перебивает). Разница не в настроении: ошибка в lua не проявляется при
СТАРТЕ движка, обработка обрывается на первом же пакете, и стратегия
«тихо не работает». Проверяет `LuaManager.check_syntax()`; когда на
устройстве нет `luac`/`lua`, проверка поверхностная, и в ответе про это
сказано (`validation.note`).

## Активные пробы и тяжёлые прогоны (S8)

### Что такое `probes` и где проходит его граница

`probes` — это **трафик, выпущенный с роутера**, а не «запись
помягче». Разрешение отдельное по двум причинам: нагрузка на
устройство и **след у провайдера** (сотня доменов подряд с одного
адреса выглядит из сети иначе, чем чтение конфига).

Граница проходит по ДЕЙСТВИЮ, а не по инструменту — тот же приём, что
у `diagnostics_run` в S5:

| Чтение (без разрешения) | Проба (`probes`) |
|---|---|
| `scan_status`, `scan_results` | `scan_start`, `scan_stop` |
| `blockcheck_status`, `blockcheck2_status`, `blockcheck2_output` | `blockcheck_start`, `blockcheck2_start`, `blockcheck2_stop` |
| `healthcheck_status` | `healthcheck_run` |
| `connectivity_matrix` (снимок) | `connectivity_matrix(refresh=true)` |
Опрос задачи — чтение: он не выпускает ни одного пакета, а без него
асинхронный контракт не работает вовсе. Остановка — проба: она меняет
состояние прогона, и право на неё есть у того, кто мог его запустить.

### `probe_compare` — контракт, на котором строится S10

```json
{"target": "rutracker.org",
 "with_bypass":    {"ok": true,  "code": "OK",      "latency_ms": 310,
                    "measured": true},
 "without_bypass": {"ok": false, "code": "tls_rst", "latency_ms": 0,
                    "measured": true},
 "verdict": "bypass_helps"}
```

`verdict` — из `probe_runner.VERDICTS` и только: `bypass_helps`,
`no_difference`, `target_down`, `bypass_hurts`, `unknown`. `code` —
из `PROBE_CODES` (`core/testers/probe.py`), никаких свободных строк:
на этих словарях держится и вердикт, и baseline эксперимента S10.

**`unknown` — это пятый вердикт, а не отсутствие ответа.** Измерить
обе стороны получается не всегда: не дали `control`, передали
`toggle=false`, не выбрана стратегия, движок не поддался. Тогда
сторона помечается `measured: false` + `reason`, и вердикт —
`unknown`. Выдуманная вторая половина здесь хуже отсутствующей: на ней
модель строит весь дальнейший подбор.

**Переключение движка требует `control` вдобавок к `probes`.** Одна
сторона измеряется в текущем состоянии устройства, вторая — после
`nfqws_control.stop()`/`start()`; это изменение состояния, а `probes`
про трафик. Без `control` инструмент **не отказывает**, а честно
отдаёт одну сторону и говорит, каким переключателем включается вторая.

**Исходное состояние возвращается в `finally`** — и после удачной
пробы, и после падения посередине. В ответе это видно полями
`engine_toggled`, `restored`, `restore_error`.

**Пустая активная стратегия ≠ «запусти как есть».** На dev-машине
движка нет и поднимать нечем: `_have_strategy()` спрашивает
`nfqws_control.active_strategy_args()`, и пустой ответ означает
честное «обхода нет», а не запуск голого nfqws2 под видом обхода.

### Асинхронный контракт (`core/mcp/tools/_jobs.py`)

Клиент рвёт HTTP-запрос через десятки секунд, а подбор и blockcheck
идут минутами. Поэтому **всё тяжёлое асинхронно**, и обратно в
синхронный вызов это не «оптимизируется»:

| Шаг | Что происходит |
|---|---|
| `*_start` | заводит запись `{job_id, kind, params, started_at}` и **сразу** возвращает `job_id` + `async: true` |
| `*_status` | живой статус runner'а; поля задачи — из `_jobs.describe()` (`job_id`, `done`, `live`, `job_note`) |
| `*_output` | инкремент по `offset` → `next_offset` (только blockcheck2) |
| `*_stop` | просит прогон остановиться и закрывает запись |

**Запись переживает конец прогона.** Модель спрашивает `*_status` и
через полминуты после завершения; «задачи нет» она прочитает как
«прогон потерян» и запустит ещё один. Держим `_jobs.KEEP` записей на
вид и кладём в запись последний увиденный статус.

**Ярлык старой задачи не отвечает живым статусом.** Runner помнит
ровно один (последний) прогон: `is_current()` сравнивает запись с
последней, и не совпало — отдаётся сохранённый снимок с `live: false`
и пояснением в `job_note`. Для `blockcheck2_output` это прямой отказ:
строк чужого прогона у нас нет, и выдать вместо них чужие — соврать.

**Один тяжёлый прогон за раз.** Движок один, и два прогона испортят
друг друга. Занятость спрашивается у той же `nfqws_control.busy()`,
что и у инструментов `control`, а в отказе называется активный
`job_id` — иначе модели нечего опрашивать. Прогон, запущенный из GUI,
ярлыка не имеет: тогда `job_known: false` и об этом сказано прямо.

### Лимиты проб (`mcp.probes`)

| Ключ | По умолчанию | Что режет |
|---|---|---|
| `max_targets` | 10 | целей в одном `probe_targets` |
| `max_repeats` | 3 | повторов пробы на цель |
| `timeout_sec` | 5 | таймаут одной сетевой операции |
| `budget_sec` | 60 | суммарное время одного вызова |
| `parallel` | 4 | одновременных проб |
| `settle_sec` | 2 | пауза после переключения движка |

Схема инструмента режет запрос на уровне протокола (`maxItems: 20`),
конфиг — на уровне устройства. Оба потолка нужны: схемный виден модели
заранее, конфигурный настраивается владельцем роутера. Лишние цели не
выбрасываются молча — они уезжают в `rejected` с причиной, а не
влезшие в бюджет времени в `skipped`.

**Повторы сворачиваются по СТРОГОМУ большинству** (`probe_runner.fold`):
домен, открывшийся один раз из трёх, работает нестабильно, и называть
это «работает» значит подсунуть модели ложную базу сравнения. В ответе
всегда есть `attempts` и `ok_count`.

### `scan_apply` — единственный инструмент с двумя разрешениями

Он делает два дела сразу: сохраняет найденное как USER-стратегию
(`strategies_write`) и поднимает с ней движок (`control`). Scope у
инструмента один, поэтому второе разрешение спрашивается внутри
обработчика (`permissions.granted("strategies_write")`) и отказ
называет его прямо. Иначе `control` в одиночку открыл бы запись
стратегий в обход `strategies_write`.

Снимок — того же вида `strategy_active`, что у `strategy_apply`:
обработчик отката один на вид и уже зарегистрирован в `tools/nfqws.py`.

## Эксперименты со стратегиями (S10)

Замкнутый цикл, ради которого затевался весь MCP: модель описывает
варианты, движок меряет каждый на одних и тех же целях и возвращает
отчёт, а состояние роутера возвращается **само**, если она не сказала
`commit`. Логика — в `core/strategy_experiment.py` (синглтон
`get_experiment_runner()`), инструменты — тонкая обёртка.

```python
runner = get_experiment_runner()
runner.start(
    variants=[{"label": "A", "args": ["--filter-tcp=443", "--lua-desync=…"]},
              {"label": "B", "strategy_id": "tcp_oob"},
              {"label": "C", "profiles": [{"args": "…"}]}],
    targets=["youtube.com", "rutracker.org"],   # пусто — core/targets.py
    repeats=2, baseline=True, ttl_sec=180, keep_best=False)
# → {"ok": True, "run_id": "exp-20260918-153012", "async": True}
```

### Как исполняется прогон

| Шаг | Что происходит |
|---|---|
| захват | `session.claim(OWNER_EXPERIMENT, timeout=0)` — **в рабочем потоке**; занято → отказ с именем держателя, синхронно |
| снимок | `session.snapshot()` + тот же снимок **на диск** (`.mcp-experiment.json` рядом с `settings.json`) |
| baseline | `nfqws_control.stop()` → пробы: что открыто и БЕЗ обхода |
| вариант | dry-run → `nfqws_control.restart(argv)` → `stabilize_sec` → пробы (`repeats`, **медиана**) → хвост лога за окно варианта → `stop()` |
| ранжирование | `score` формулой сканера, `best` — первый, кто реально что-то починил |
| решение | `keep_best` → лучший остаётся применённым, поток ждёт `commit` до дедлайна |
| возврат | в `finally`: `stop()` → `session.restore(snapshot)` → снимок с диска убирается |

### Три вещи, которые легко сломать обратно

**Мьютекс держит рабочий поток — и решение исполняет он же.** Захват
потоко-привязан (`held_by_me()` смотрит на `threading.get_ident()`), а
`commit`/`rollback` приходят из потока HTTP-запроса. Поэтому они не
трогают движок сами, а кладут решение в `_decision` и ждут ответа
рабочего потока (`DECISION_WAIT_SEC`). Сделать «проще» — значит либо
отпустить мьютекс на время ожидания `commit` (и дать сканеру снять
снимок с ВРЕМЕННОЙ стратегии, а потом «вернуть» роутер к ней), либо
получить `SessionBusy` на собственном захвате.

**Перед `restore()` движок надо погасить.** `NfqwsSession.restore()`
идемпотентен по СОСТОЯНИЮ, а не по аргументам: «снимок говорит
запущен, движок запущен — шага нет». После эксперимента это означало бы,
что временная стратегия так и осталась. Поэтому `_stop_engine()` перед
возвратом — тот же двухуровневый приём, что у `_ensure_cleanup` сканера.

**`keep_best` — это НЕ `commit`.** Вариант, оставленный применённым,
живёт до дедлайна и откатывается сам; `state` становится `reverted`,
`expired: true`. Подтверждение — только явный `commit`, и до него
`awaiting_commit: true` висит и в статусе, и в отчёте.

### Отчёт: что в нём есть и почему

`get_result()` → `run_id`, `state`, `targets`, `baseline` (по целям +
`open_without_bypass`), массив `variants`, `ranking`, `best`,
`warnings`. По варианту: `validation` (dry-run), `started_nfqws`,
`per_target` (код из `PROBE_CODES`, латентность-медиана, `bytes_read`,
`kbps`), `success_rate`, `score`, `delta_vs_baseline`
(`fixed`/`broken`/`unchanged`/`net`), `nfqws_log` (≤ 20 строк) и
`hints`.

- **`score` — формула сканера** (`strategy_scanner.compose_score`), и
  это не вкусовщина: разойдись они, «лучший вариант» эксперимента и
  «лучшая стратегия» в UI были бы разными строками на одних измерениях.
- **`best` требует починки, а не только score.** У варианта на уже
  открытой цели score ненулевой (так считает сканер), но чинить было
  нечего: при измеренном baseline победителем становится только тот,
  у кого непустой `fixed`. Иначе прогон по открытому домену выдавал бы
  «находку».
- **Хвост лога режется по ОКНУ варианта** (`_log_window(start, end)`).
  Без этого в отчёт уезжает лог предыдущего варианта, и модель чинит не
  то, что сломано.
- **Латентность — медиана** (`probe_runner.fold(latency="median")`).
  Один выброс на роутере — норма, среднее из трёх замеров он
  переставляет варианты местами.
- **QUIC мы не меряем.** `probes=["quic"]` уезжает в
  `probes_unsupported` с причиной: движок меряет одной цепочкой DNS →
  TCP → TLS → HTTP, и выдуманный замер хуже отсутствующего.
- Отчёт отдаётся **страницей** (`_paging.page` по вариантам, лучший
  первым): он же ужимается под `mcp.limits.response_kb`.
  `include_log=false` убирает хвосты лога — вдвое больше вариантов в окне.

### Правила-подсказки — данные, а не `if`

`HINT_RULES` в `core/strategy_experiment.py`: список записей
`{id, when, patterns|rule, hint, ref}`. S11 дополняет **список**, не код.

| `when` | Как сопоставляется |
|---|---|
| `log` | все подстроки `patterns` в **одной** строке хвоста лога, регистр не важен |
| `metric` | предикат из `_METRIC_RULES` по измерениям варианта |

Подстрок несколько намеренно: реальная строка выглядит как
`rawsend: sendto: Operation not permitted`, и одной подстрокой её не
поймать, а склеивать весь лог в один текст нельзя — «rawsend» из первой
строки и «not permitted» из десятой это две разные беды.

Минимальный набор (таблица задания S10): `rawsend_eperm` → POSTNAT и
`desync_mark_postnat`; `lua_nil_call` → `lua_functions_list`;
`zero_everywhere` (валидный dry-run, 0 % на всех целях) → правила
NFQUEUE и `queue_num`; `engine_did_not_start` → `--user` и права. Сверх
них — `hostlist_missing`, `blob_missing`, `queue_bind_failed`,
`dry_run_failed`, `worse_than_baseline`. У каждого правила обязателен
`ref`: подсказка без адреса отправляет модель искать наугад (есть
тест-сторож).

### Дедмен-свитч и выключение питания

TTL отсчитывается от старта прогона и покрывает его целиком, включая
ожидание `commit` (`ttl_left_sec` в статусе). Отдельного потока-дедмена
нет: ждёт тот же рабочий поток, который держит мьютекс, — так решение и
возврат исполняет один владелец, а не двое наперегонки.

Снимок дублируется **на диск** (`MARKER_NAME = ".mcp-experiment.json"`),
потому что TTL не переживает выключения питания. При старте GUI
`recover_after_restart()` (зовётся из `_apply_autostart_on_boot` в
`app.py`, ДО `reapply_if_missing()` и автозапуска) возвращает состояние
по этому снимку и убирает файл. Это пункт 3 приёмки фичи целиком.

### Разрешения

Все семь инструментов — под `experiments`, и оно не действует без
`control` и `probes` (`permissions.REQUIRES`). Опрос и отчёт **не**
вынесены в чтение, в отличие от сканера: у сканера статус описывает
прогон, запущенный кем угодно, а здесь и статус, и отчёт — результат
изменений, которые внесла сама модель.

`commit(save_as=…)` сверх того спрашивает `strategies_write` — тот же
приём, что у `scan_apply`: иначе `experiments` открыл бы запись
стратегий в обход. `make_active` без `save_as` — отказ: активной
делается сохранённая стратегия, а не временный argv.

## Сборка и проверка стратегий (S11)

Два инструмента в `tools/compose.py` и один чистый модуль
`core/strategy_lint.py`. Замыкают цикл §8.4 плана: **собрал →
проверил → сохранил → применил → измерил → откатил**.

### Почему проверок две, а не одна

| Что ловит | `nfqws2 --intercept=0` | линтер |
|---|---|---|
| разбор опций CLI | да | нет |
| отсутствующие файлы (`--blob`/`--hostlist`/`--lua-init`) | да | частично |
| ошибку ВНУТРИ lua (синтаксис, порядок `--lua-init`) | **да** | нет |
| вызов несуществующей `--lua-desync` | **нет** | **да** |
| незаявленный blob | **нет** | **да** |
| приём без фильтра профиля | нет | да |

Правая колонка — это ровно «тихий 0%»: вызов функции происходит
по-пакетно, а незаявленный blob с zapret2 1.0.4 сносится в C-коде ещё
до входа в Lua. Движок стартует, код выхода 0, обхода нет и в логе ни
строки. Поэтому в ответе обоих инструментов **всегда оба поля**:
`lint` и (у `strategy_validate`) `validation`.

### `strategy_compose` — описание вместо строки

Вход — декларативные профили; формат один и тот же у обоих
инструментов (два разных формата под именем `profiles` модель путала бы
гарантированно):

```json
{"profiles": [{"filter": {"proto": "tcp", "ports": "443", "l7": "tls",
                           "hostlist": "youtube"},
                "payload": "tls_client_hello", "out_range": "-d10",
                "desync": [{"fn": "fake",
                             "params": {"blob": "tls_google",
                                        "tcp_md5": true, "repeats": 11}}],
                "blobs": ["tls_google"]}]}
```

- порядок сборки — по §15 скила nfqws2: **фильтр профиля →
  внутрипрофильные фильтры (`out_range`/`in_range`/`payload`) →
  инстансы**. Он значим: `--payload` действует на СЛЕДУЮЩИЕ
  `--lua-desync` (§3.4);
- `params`: `true` — ключ без значения (`:tcp_md5`), `false` — не
  ставить вовсе, число — как есть. Двоеточие в значении экранируется,
  значение с пробелом заворачивается в одинарные кавычки (идиом
  inline-Lua `code='desync.x = 1'`);
- `filter.hostlist`/`ipset` — **имя списка, а не путь**: превращается в
  `lists/<имя>.txt`, который резолвится в путь устройства
  `CatalogManager.resolve_paths_in_args`. `../../etc/passwd` — отказ, а
  не санитизация;
- `blobs` — только для имён, которых движок по ссылке не найдёт
  (`pattern=`, `seqovl_pattern=`, `%NAME`). Ссылки `blob=NAME`
  дозаявляет сам `build_nfqws_args`. Декларации кладутся в НАЧАЛО
  первого профиля: они глобальны и читаются до первого `--new`;
- ответ содержит `profiles` в том виде, в каком их принимает
  `strategy_save` — перекладывать руками нечего.

**Сборка не дублируется ни строкой.** Декларативное описание
превращается в строку аргументов
(`strategy_builder.compose_profile_args`), а дальше идёт через тот же
`build_nfqws_args`, что и стратегия из веб-интерфейса: автообёртка
голого приёма, дозаявка блобов, резолв путей. Сторож —
`test_argv_matches_a_handwritten_strategy`.

### Ошибка линтера делает ответ `isError`

Пункт приёмки S11: стратегия с несуществующей lua-функцией **не
доходит** до эксперимента. Движок экспериментов проверяет варианты
через `dry_run`, а тот такую функцию пропускает — значит, отбить её
может только здесь. Поэтому при `lint.blocking` **или** провале
`dry_run` ответ — `ok: false`, но `strategy_args`, `command` и
`profiles` **остаются в нём**: модель должна видеть, что чинить.
Предупреждение (`severity: warning`) ответ не роняет никогда, и поле
`valid` называет вердикт одним булевым.

### Линтер — `core/strategy_lint.py`, а не внутри MCP

Чистые функции без I/O: окружение (`known_functions`, `known_blobs`)
приходит **аргументами**. Поэтому им пользуется и страница стратегий, и
обычный юнит-тест, которому не нужен ни роутер, ни поднятый сервер.
Окружение собирает вызывающий (`tools/compose._known_functions` /
`_known_blobs`); `None` означает «правило не проверяем» — объявить
неизвестной каждую функцию хуже, чем не проверить ни одной
(`lint.checked` в ответе говорит, что удалось сверить).

| `code` | Уровень | О чём |
|---|---|---|
| `bare_trick_no_filter` | warning | `--lua-desync` без `--filter-tcp/udp/l7`: уедет на весь трафик очереди |
| `unknown_lua_function` | **error** | имени нет в карте этого устройства |
| `blob_unknown` | **error** | `blob=NAME` не объявлен и не известен реестру |
| `blob_file_missing` | **error** | объявлен, но файла нет — ПУСТОЙ fake |
| `blob_declared_after_new` | **error** | `--blob=` после `--new` (декларации глобальны, §2 инв. 6) |
| `lua_init_order` | **error** | `zapret-lib.lua` грузится не первым (§2 инв. 1) |
| `l7_filter_without_ports` | warning | `--filter-l7=tls/http/quic` без портов |
| `no_desync_action` | warning | в argv нет ни одного `--lua-desync` |
| `engine_owned_option` | **error** | в стратегии опция, которой владеет GUI (`--user`/`--uid`/`--qnum`/`--fwmark`/`--pidfile`/`--daemon`/`--writable`/`--intercept`/`--dry-run`, `--debug=@файл`) — сборщик её вырежет |

### Аргументы стратегии: чем владеет GUI

Стратегия — произвольный argv из редактора, каталога или MCP, и в
команду она встаёт ПОСЛЕ базовых аргументов, где побеждает последнее
значение. Поэтому `NFQWSManager.compose_command` вырезает из неё
(`_strip_engine_owned`, список — `strategy_lint.ENGINE_OWNED_OPTIONS`,
в лог — warning):

* `--qnum`/`--fwmark` — ломают перехват и собственный трафик GUI (те же
  поля закрыты для `config_set`), `--user`/`--uid` — отменяют сброс
  прав, и lua стратегии идёт от root;
* файловые примитивы, которые nfqws2 выполняет **от root на разборе
  опций**, ещё до сброса прав (сверено по nfq2/nfqws.c и
  nfq2/darkmagic.c): `--pidfile` (запись куда скажут), `--writable`
  (`chown` каталога, и существующего тоже), `--debug=@файл`
  (`fopen("wt")` — обнуляет файл), `--hostlist-auto=`/
  `--hostlist-auto-debug=` вне каталогов списков (`chown` файла);
* `--daemon` (процесс уходит из-под присмотра), `--intercept`/
  `--dry-run` (запуск превращается в проверку).

Сюда же две соседние границы:

* `dry_run` снимает `--user` **только без root** (dev-машина). От root
  сброс прав обязателен: lua-init стратегии с `io.open` иначе исполнялся
  бы от root, и `strategy_validate` под одним `strategies_write` был
  бы записью в любой файл роутера. `os.execute`/`io.popen` nfqws2
  вырезает сам (`lua_sec_harden`), `io.open` — нет;
* `_ensure_list_files` создаёт недостающий список только внутри
  `_write_roots()` (каталоги zapret, конфиг GUI, `/tmp`): создание идёт
  от root, и пустой `/etc/nologin` «как список» закрыл бы вход в
  систему.

**Линтуется собранный argv**, а не строка из редактора: иначе линтер
ругался бы на то, что сборщик чинит сам (`autowrap_bare_trick`).

**Сторож против шума — `test_builtin_strategies_have_no_lint_errors`:**
линтер прогоняется по ВСЕМ 730+ встроенным стратегиям, и ошибок там
быть не должно ни одной. Он же поймал два ложных правила на этапе
написания: `blob=0x0000…` — это инлайновый hex, а не имя (53 ложные
ошибки), а `tls_rnd`/`tls_youtube` объявляет `init_vars.lua`, а не
реестр блобов (`nfqws_manager.lua_named_patterns()`).

### Правила-подсказки: S11 дополнил список

Три новых `log`-правила из чеклиста §16 скила nfqws2:
`lua_compat_mismatch` (compat 5≠6 после обновления движка),
`reasm_queue_overflow` (`rawpacket_queue failed !` — §8.10),
`lua_bad_argument` (`bad argument #2 to 'tls_mod'` — порядок
`--lua-init`, §12.1). Список **один на проект** —
`strategy_experiment.HINT_RULES`; `strategy_validate` зовёт тот же
`hints_for()`.

## Shell и система (S12)

Логика — в `core/shell_exec.py` (**не в пакете MCP**): её же получат
диагностика и будущий терминал в GUI. `tools/shell.py`, `files.py`,
`packages.py`, `services.py`, `system.py` — обёртки: разрешения, схема,
форма ответа.

### Два режима и граница между ними

| Режим | Как запускается | Чем закрыт |
|---|---|---|
| `argv` | `["df", "-h"]` без оболочки: ни пайпов, ни подстановок | safe-список, `shell_readonly` |
| `sh -c` | строка ОДНИМ аргументом в `["sh", "-c", command]` | `shell_full` |

**Строка под `shell_readonly` принимается** — но только без
метасимволов (`SHELL_META_RE`): она разбирается `shlex` и исполняется
argv-режимом. Задание требовало «только argv-режим», и это он и есть:
оболочки в этом пути нет вовсе. Иначе модель, которой естественно
написать `command="df -h"`, получала бы отказ на каждой первой команде.

**Safe-список исполняет НОРМАЛИЗОВАННЫЙ argv.** `busybox ls` → `ls`,
`/bin/ls` → `ls`, и именно `ls` уезжает в `execvp` по нашему
фиксированному `PATH`. Иначе `/tmp/evil/ls` проходил бы проверку по
имени `ls`.

### Safe-список — данные, а не цепочка `if`

`SAFE_COMMANDS`: имя → `{letters, flags, value_flags, numeric, first,
deny, args, require, forbid}`. `letters` — склеиваемые однобуквенные
флаги (`iptables -nvL` разбирается на `-n`,`-v`,`-L`), `value_flags` —
флаги со значением в обеих формах (`-n 1` и `-n1`), `first` —
допустимый первый позиционный аргумент (`nft list`, `wg show`),
`deny` — глаголы, превращающие читающую команду в меняющую
(`ip … set`, `route del`), `require` — что обязано быть (`ping -c`,
`iptables -L/-S`).

**Чего в списке нет и почему:** `find` (`-exec`, `-delete`), `awk`
(`system()`, `print > file`), `sed` (`-i`, `w`), `env`, `nc`, `wget`,
`sh`. У каждой из них одна пропущенная опция превращает «чтение» в
root-доступ, а список расширяется **здесь, в скиле**, а не наспех в
коде.

### Три уровня защиты, и они разные

1. **`DENY_RULES` — отказ, не обходится ничем.** Перепрошивка, `mkfs`,
   `dd of=/dev/…`, `rm -rf` по защищённому корню, смена пароля root,
   форк-бомба. Подтверждения для них не существует: `confirm_token` в
   ответе не появляется вовсе.
2. **`CONFIRM_RULES` — два шага.** Первый вызов → `isError` +
   `confirm_token` (одноразовый, 60 с) + человеческое описание
   последствий; второй — `shell_confirm(confirm_token=…)`.
3. **`guard` — дедмен-свитч.** Правила с `network: true` (`iptables
   -F`, `nft flush`, `ip link set … down`, остановка `dropbear`,
   правка маршрутов) без `guard` **не выполняются вовсе**. С ним после
   команды заряжается таймер: не пришёл `shell_confirm(run_id=…)` —
   выполняется `revert_cmd`.

**Порядок проверок неслучаен:** запрет → guard → подтверждение. Если
бы подтверждение шло раньше, модель получала бы токен, подтверждала —
и только тогда узнавала, что нужен ещё и дедмен.

### Нормализация: без неё защита декоративная

`normalize_text()` снимает кавычки и обратные слэши (`r\m` → `rm`),
схлопывает пробелы, выкидывает префиксы (`env`, `sudo`, `busybox`,
`VAR=1` и их флаги) и путь у самой команды (`/bin/rm` → `rm`), а
каждый сегмент (`;`, `|`, `&&`) нормализует отдельно. Тест
`test_mcp_shell_guards.OBFUSCATED` перебирает восемь способов обойти
наивное сравнение — все они обязаны отклоняться.

Обратная сторона проверяется там же: `rm -rf /opt/zapret2/tmp/build`,
`cat /etc/passwd` и `grep -r password /opt/etc` запрещены быть НЕ
должны. Правило, которое ловит всё, ничем не лучше правила, которое не
ловит ничего.

### Дедмен живёт на диске

`mcp-shell-guards.json` рядом с `settings.json` (`platform_dirs
.config_dir()`), **не в /tmp**: там tmpfs. Таймер в памяти процесса,
который сам же и падает, не откатывает ничего — поэтому при старте GUI
`shell_exec.recover_guards()` (зовётся из `app.py` рядом с
`recover_after_restart()` экспериментов): просроченные исполняются
немедленно, живые перезаряжаются. Срабатывание идемпотентно —
единственный источник правды — состояние записи на диске (`armed` →
`firing` → `fired`/`confirmed`).

Событие дедмена уходит и в лог (`source="shell"`), и в журнал MCP
(`shell_guard_revert`).

### Правила исполнения

| Правило | Как сделано |
|---|---|
| `stdin` закрыт | `stdin=DEVNULL` — интерактивная программа не повиснет |
| окружение минимальное | `BASE_ENV` (`PATH`, `HOME`, `LANG=C`, `TERM=dumb`), **ни одной переменной процесса GUI** |
| таймаут обязателен | `SIGTERM` всей группе (`start_new_session=True` + `killpg`), через 3 с — `SIGKILL`; в ответе `timed_out` |
| вывод слит и обрезан | `stdout`+`stderr` в один поток, обрезка до `output_kb` **с хвоста** (в хвосте ошибка), пояснение — в `output_note` |
| секреты вырезаны | `redact_text()` внутри `core/shell_exec.py` — до журнала и лога, а не только в ответе |
| одна синхронная за раз | нежёсткий `_sync_lock`; занято — отказ с подсказкой про `shell_exec_async` |
| фоновых ≤ `max_jobs` | отказ называет `job_id` активных |

`ok` — это «команда выполнилась сама», а не «вернула ноль»: `grep`,
ничего не нашедший, отвечает кодом 1, и ошибкой вызова это не
является (иначе модель начнёт «чинить» исправное). Таймаут — `ok:
false`: команда не завершилась.

### Фоновые задачи — свой реестр, не `_jobs.py`

`_jobs.py` устроен вокруг singleton-runner'ов (сканер, blockcheck):
«один прогон на вид», `is_current()`. У shell задач несколько
одновременно, и каждая держит собственный процесс, — поэтому реестр
свой, в `core/shell_exec.py`. Контракт снаружи тот же: `*_async` →
`job_id` сразу, `shell_job_status`, `shell_job_output(offset)` →
`next_offset`, `shell_job_stop`; завершённая задача продолжает
отвечать (`JOBS_KEEP`).

**Буфер фоновой задачи хранит НАЧАЛО, а не хвост** (в отличие от
синхронного вызова): её вывод читают по `offset`, и выкинуть начало
значит сломать нумерацию. Читается он через `read1()`, а не `read()`:
у буферизованного потока `read(n)` ждёт ровно `n` байт, и вывод
появлялся бы у модели только после завершения команды.

### Файлы

`file_read` — окно (`offset`/`limit_kb`/`tail`), `file_list` — поля
вместо строки `ls -l`, `file_write` — только внутрь
`mcp.shell.allow_write_paths`, **по резолвнутому пути** (симлинк из
разрешённого каталога наружу — готовая дыра), атомарно
(`safe_io.atomic_write_bytes`), **с сохранением прав** (атомарная
запись создаёт новый файл, и init-скрипт терял бы `+x`).

Прежняя версия уезжает снимком `audit.KIND_FILE` целиком (текстом или
base64). Файл крупнее `MAX_BACKUP_BYTES` на запись **не принимается**:
изменение без пути назад противоречит §5.4 контракта. Собственные
файлы GUI (`settings.json`, журнал, снимки, файл дедменов) не правятся
вовсе — иначе модель дописала бы себе разрешения.

### Пакеты и службы

`opkg`/`apk` выбирается по факту (`shutil.which`), имя пакета
валидируется регуляркой, команда собирается **argv-списком** — подстановки
в строку нет нигде. Установка и удаление обратимы (`KIND_PACKAGE`:
снимок помнит, стоял ли пакет), удаление требует подтверждения.

Имя службы **сверяется со списком найденных скриптов** — в команду
уезжает путь, прочитанный с диска, а не присланная строка. Понимается
и короткое имя (`demo` → `S99demo`). `stop`/`start` обратимы
(`KIND_SERVICE`), у `restart`/`reload` обратного действия нет — и
снимка они не делают.

### Журнал отвечает «что получилось»

`audit.note(**поля)` — новая точка (S12): кладёт в запись журнала
`result` (код возврата, первые строки вывода, путь, имя пакета).
Аргументы говорят, что модель просила; для shell этого мало. Поля
проходят ту же маскировку, что аргументы.

### `confirm_token` — единственное исключение в маскировке

Слово `token` подходит под `SECRET_KEY_RE`, и токен подтверждения
уезжал моделью как `***` — то есть двухшаговое подтверждение не
работало вовсе. Он добавлен в `redact.PUBLIC_KEYS`: одноразовый (60 с)
ярлык, бесполезный для всех, кроме того, кто его только что получил.
Список точечный; общее правило («поле назвали не так») по-прежнему
решается переименованием поля.

## Самоправка кода GUI (S13)

Самый опасный набор: MCP-сервер живёт **внутри** того процесса, который
модель переписывает. Отсюда вся конструкция — `core/code_editor.py`
(границы, staging, проверки, снимки) и `core/code_guard.py`
(**посторонний процесс**, который откатывает).

### Правка не попадает на диск до `code_apply`

`code_patch`/`code_write` пишут в staging-копию рядом с `settings.json`
(`<config_dir>/code-staging/`), а не в файл проекта. Поэтому «битый
синтаксис до диска не доезжает» — свойство механики, а не дисциплины
вызывающего: даже при падении GUI посреди вызова на диске проекта
ничего не изменилось.

Цепочка правок работает: второй `code_patch` по тому же файлу видит
результат первого (`current_bytes` смотрит в staging раньше, чем на
диск). Выкинуть накопленное — `code_patch(drop=true)` (с `path` — одну
правку, без — все); отдельного инструмента на это нет намеренно, набор
и так тринадцать штук.

### Слепок дерева вместо «проверим после применения»

`ast.parse` ловит опечатку, но не ловит главного: модуль может не
импортироваться (сломанный импорт, `raise` на уровне модуля, имя,
которого больше нет). Импортировать staging-копию под настоящим именем
нельзя — её нет в дереве.

`code_editor.build_shadow()` собирает каталог, где **на всё стоят
симлинки** в настоящий проект, а каталоги по пути к правленым файлам
сделаны настоящими и правленый файл лежит в них реальным файлом. Дальше
`python3 -B -E -s -c "import core.foo"` с `cwd` слепка импортирует
именно правку, а зависимости берёт из настоящего дерева. Симлинки на
роутере бесплатны, копирование проекта — нет.

Три вещи, которые легко сломать обратно:

- **`-B` (не писать `.pyc`)**: каталог `vendor` в слепке — симлинк, и
  `__pycache__` уехал бы по нему в настоящее дерево;
- **`__pycache__` в слепок не переносится вовсе** — иначе проверка
  «прошла бы» на старом байт-коде (ровно грабля из задания);
- **слепок собирается по ВСЕМ накопленным правкам**, даже если проверить
  просят одну: применятся они вместе, и модуль, проверенный в дереве без
  остальных правок, проверен не в том дереве.

`code_check` = разбор (`.py` → `ast`, `.json` → `json.loads`, `.js` →
`node --check`, если node есть) → импорт из слепка → `lint_tree()`
(разбор **всех** `.py` проекта, эквивалент `make lint`: правка часто
ломает не свой файл, а соседний) → опционально `pytest` (тоже по
слепку). Подпроцессы гоняются через `shell_exec.execute()` — второго
механизма запуска в проекте нет.

### Снимок и его состояния

`<config_dir>/code-snapshots/<snap-YYYYmmdd-HHMMSS>/`: `manifest.json` +
`files/<относительный путь>` с ПРЕЖНИМ содержимым. Манифест пишется
**до** правки файлов — выключение питания посреди применения обязано
оставлять опись.

| Состояние | Что значит |
|---|---|
| `pending` | файлы положены, сторож ещё не судил |
| `applied` | GUI ответил после перезапуска, ждём `code_commit` |
| `committed` | подтверждено моделью, дедмен снят |
| `reverted` | возвращено (сторожем по health/TTL, `code_rollback` или `mcp_undo_last`) |

**Снимки сортируются по времени из манифеста, а не по имени.** Имя
уникально только в пределах секунды, а после ротации освободившееся имя
переиспользуется: сортировка по строке однажды объявила бы самый новый
снимок самым старым и выкинула его (ловится
`test_reused_name_does_not_confuse_the_order`). Ротация (`snapshots_keep`)
**никогда не трогает незакрытый снимок** — им откатывают.

Второй `code_apply` при неподтверждённом первом отклоняется: две
неподтверждённые правки подряд нечем откатывать. Ещё одна проверка —
**дрейф**: если файл изменился на диске между правкой и применением
(обновление GUI, правка по ssh), применение отклоняется с перечнем
файлов, а не затирает чужую запись.

### Сторож — посторонний процесс, и это единственное, что делает схему рабочей

`python3 -B -m core.code_guard --snapshot <id> --timeout <сек>
--commit-ttl <сек> --config-dir <кат>`, запускается из `code_apply`
с `start_new_session=True` **до** просьбы о перезапуске.

- **Ни одного нашего импорта.** Настройки читаются прямым `json.load`
  из `settings.json`, файлы возвращаются своими руками, команда
  перезапуска берётся из манифеста (её вычислил ещё живой GUI). Модуль,
  который возвращает сломанный код, не может зависеть от сломанного
  кода; 30 строк атомарной записи продублированы сознательно, а
  расхождение констант ловит `test_states_match_the_editor`.
- **Проверка «GUI жив» — тело `/api/status`, а не TCP-коннект.** Порт
  держит и наполовину поднявшийся процесс, и чужая программа, занявшая
  его после падения нашей.
- **Ложный откат исправного GUI хуже отсутствия отката.** Поэтому первым
  делом сторож проверяет, отвечает ли GUI **прямо сейчас** (его запустил
  живой GUI). Не отвечает — значит, проверка недостоверна (пароль, порт,
  bind), и сторож работает только по дедмену подтверждения.
- **«Не ушёл на перезапуск» — не провал.** Код лежит на диске
  незагруженным; решает дедмен подтверждения.
- Манифест правят двое (сторож и `code_commit`), поэтому сторож
  дописывает **только свои поля** в свежую копию с диска (`_patch`), а
  закрытый чужой рукой снимок обратно в «ждём» не поднимает.
- Причина отката уходит в **персистентный** `<config_dir>/code-guard.log`:
  «всё само откатилось» без объяснения — худший исход.

### Разрыв соединения: текст один на три места

`code_apply` перезапускает GUI, и MCP-клиент видит ошибку транспорта.
Это норма, и сказано об этом трижды одинаково: в описании `code_apply`
(модель читает его ДО вызова), в `hint` ответа и во врезке
`server._instructions` (появляется, когда включён `self_edit`):

> после code_apply соединение оборвётся: подождите 5–10 секунд,
> повторите `system_status` и вызовите `code_commit`

Без этой врезки модель читает разрыв как «правка не прошла», пробует
снова и получает отказ «предыдущая не подтверждена» — при том что сторож
уже отсчитывает TTL.

### Границы и защищённое ядро

Корень — каталог установки GUI (автодетект по `__file__`,
переопределяется `mcp.self_edit.root`). Путь резолвится **по
существующей части**: `..` после `normpath` уже не виден, а каталог в
середине пути может быть симлинком наружу. Собственные файлы GUI
(`settings.json`, журнал MCP, снимки, файл дедменов) не правятся вовсе.

`self_edit_core` спрашивается **по месту** (как `shell_full` у
`shell_exec`) и проверяется дважды: при укладке правки в staging и при
`code_apply` — разрешение могли выключить между ними. Список
`mcp.self_edit.protected` — **пол, а не потолок**: `CORE_PROTECTED` в
`code_editor.py` добавляет к нему `code_editor.py`, `code_guard.py`,
`mcp/auth.py`, `mcp/permissions.py`, `mcp/registry.py`,
`config_manager.py`. Расчехлить сторожа, убрав его из `settings.json`,
нельзя.

### Маскировка: единственный ответ, где `redact_text` НЕ применяется

`file_read` (S12) чистит содержимое файла текстом — там `/opt/etc/*.conf`
с ключами. `code_read`/`code_search`/`code_diff` этого не делают
намеренно: исходники GUI секретов не содержат (они в `settings.json`, а
он вне корня и запрещён), зато маска ломает **точное совпадение** в
`code_patch` — строка `token = cfg.get(...)` уехала бы как `token = ***`
и правка по ней не легла бы никогда. Маскировка по ключам
(`registry.tool_result`) работает как везде.

### Правки живут до обновления GUI

`code_export_patch` собирает их одним unified diff относительно **самой
ранней** сохранённой версии файла (эталон берётся из старейшего снимка,
где файл встречается). Та же сводка приезжает предупреждением в
`updates_check` и в `gui_updater.get_version_comparison()`
(`local_code_changes`): обновление затирает правки без следа, и сказать
об этом надо ДО, а не после.

### Что переживает перезагрузку

`code_editor.recover_after_restart()` зовётся из `app.py` рядом с
восстановлением экспериментов (S10) и дедменов shell (S12): выключение
питания убивает и GUI, и сторожа, а правка остаётся на диске
неподтверждённой. Просроченные снимки возвращаются немедленно, живым
перезаряжается сторож (`--no-restart-wait`: GUI уже поднят, ждать
перезапуска незачем).

### Настройки (`mcp.self_edit`)

| Ключ | Дефолт | Что значит |
|---|---|---|
| `root` | `""` | пусто = автодетект каталога установки |
| `snapshots_keep` | 20 | сколько снимков хранить |
| `restart_timeout_sec` | 45 | сколько сторож ждёт `/api/status` |
| `commit_ttl_sec` | 300 | сколько ждёт `code_commit` |
| `run_tests` | false | гонять ли pytest перед применением |
| `protected` | 4 пути | дополнение к `CORE_PROTECTED` |

## Транспорты и CLI (S14)

Три двери в один и тот же диспетчер. Ни одна не заводит своей логики
вызова: `server.dispatch` и `registry.call` те же самые, разрешения те
же самые.

| Дверь | Когда нужна | Включается |
|---|---|---|
| `POST /api/mcp` | основной путь, клиенты 2025-03-26+ | всегда |
| `GET /api/mcp/sse` + `POST /api/mcp/messages` | клиент умеет только схему 2024-11-05 (часть сборок LM Studio, старые Cline) | `mcp.transports.sse` |
| `zapret-gui mcp --stdio` | клиент на ноутбуке, роутер за NAT: `ssh router zapret-gui mcp --stdio` | всегда (канал даёт ssh) |

### Legacy-SSE: два канала вместо одного

1. `GET /api/mcp/sse` → первым событием `event: endpoint`, данные —
   **адрес строкой** (`/api/mcp/messages?session=<id>`), не JSON: так
   сказано в спеке ревизии 2024-11-05;
2. `POST /api/mcp/messages?session=<id>` → **`202` и пустое тело**;
3. ответ приезжает в поток событием `event: message`.

Ответа в теле POST нет и быть не может — клиент этой схемы читает
только поток. Поэтому `_deliver()` кладёт ответ в очередь сессии, и
единственный случай, когда POST отвечает не `202`, — переполненная
очередь (`503`: поток не читают).

Принимаем `?session=`, `?sessionId=` и `Mcp-Session-Id`: свой адрес мы
отдаём с `session=`, но клиенты со старых SDK шлют `sessionId`.

**Флаг читается на каждом запросе** (`session.sse_enabled()`) —
включение и выключение SSE не требует перезапуска GUI. Выключенный
транспорт отвечает `404` с текстом, а не молчанием.

### Сессия живёт, пока идёт поток

`core/mcp/session.py` держит только очередь доставки — ни разрешений,
ни состояния протокола. Живость подтверждается **ходом самого
потока**: генератор зовёт `touch()` на каждом круге (не реже
`KEEPALIVE_SEC = 15`), `sweep()` выметает молчащих дольше
`IDLE_TIMEOUT_SEC = 90`. Уборка вызывается из обычных операций
(`open_session`, `get`, `count`) — отдельного потока-сторожа нет: тред
ради четырёх записей в словаре на роутере со 128 МБ не окупается.

Штатный путь другой: разрыв клиента роняет `GeneratorExit`, генератор
закрывает сессию в `finally`. `sweep` — сеть под этим, на случай
сервера, бросившего генератор не закрыв.

Сессию заводит **обработчик, а не генератор**: после первого `yield`
заголовки уже ушли, и честный `429` на превышение
`mcp.limits.max_sessions` не выйдет.

### `notifications/tools/list_changed` — опросом, а не крючком

Разрешения меняются из трёх мест: `config_set`, страница настроек GUI,
руками в `settings.json`. Крючок пришлось бы вешать в каждое;
`session.poll_permissions()` на круге keep-alive ловит все три и стоит
одного чтения конфига раз в 15 секунд. Снимок разрешений заводится при
открытии первой сессии — иначе первый же опрос счёл бы «ничего → что-то»
сменой и разослал лишнее уведомление.

### stdio-мост: чего нельзя нарушать

- **одна строка — один JSON-RPC объект** (или батч-массив);
- **stdout священен.** Одно `print()` в любом импортированном модуле
  ломает протокол, поэтому на время работы `sys.stdout` подменяется на
  `stderr`, а настоящий дескриптор остаётся только внутри `serve()`.
  Отладка — через stderr;
- **мусор в stdin → `-32700`, мост живёт дальше.** Одна кривая строка
  не заканчивает сессию;
- **EOF завершает** мост нулём — клиент закрыл канал, это норма;
- **уведомление ответа не порождает** — `dispatch` вернул `None`, в
  stdout не уходит ничего;
- **в stdout пишут двое — и только под одним замком.** Ответы пишет
  поток, читающий stdin, уведомления — поток-писатель `_Notifier`. Две
  строки наперегонки склеиваются в одну нечитаемую.

**Уведомления по stdio (подписка и `tools/list_changed`).** stdin
читается в один поток, и пока он ждёт строки, сказать клиенту что-то
самому мосту нечем. В локальном режиме рядом работает `_Notifier`: у
моста своя `session.Session` — та же, что у legacy-SSE, но **вне
общего реестра** (это отдельный процесс, и `max_sessions`/`sweep` к
нему отношения не имеют), — и он крутит ровно круг SSE-генератора:
`session.poll_resources(targets=[своя сессия])` и сверка разрешений
раз в `KEEPALIVE_SEC` (`session.permissions_snapshot()`, снимок свой).
Сессия уходит в `ctx["session"]`, поэтому `initialize` честно
объявляет `resources.subscribe: true`. EOF останавливает писателя и
дожидается его (`stop()` будит очередь `None`'ом): после конца моста в
stdout не пишет никто. В прокси-режиме писателя нет — чужая точка
stateless, и подписку она отклонит сама.

Локальный режим работает и при `mcp.enabled=false`: доступ дал ssh, а
не токен (в stderr об этом пишется строка). Прокси-режим (`--url`,
`--token`) заворачивает недоступность точки в JSON-RPC-ошибку с тем же
`id` — без ответа клиент висит до собственного таймаута, и причина
видна только здесь.

### `zapret-gui mcp …`

| Команда | Что делает |
|---|---|
| `mcp status` | включён ли, адрес, транспорты, разрешения (с пометкой «стоит, но не действует»), сколько инструментов видит модель |
| `mcp token show` | печатает токен — осознанно, иначе его не скопировать по SSH; предупреждает про историю shell |
| `mcp token rotate` | новый токен на диск; предупреждает, что подключённые клиенты оборвутся |
| `mcp tools [--json]` | что видит модель при текущих разрешениях |
| `mcp call <tool> '<json>'` | локальный вызов через тот же реестр; код возврата 1 — `isError`, 2 — аргументы |
| `mcp audit [--limit N]` | журнал вызовов, включая shell-команды |
| `mcp code list\|diff\|rollback\|export-patch` | снимки самоправки; без S13 честно говорит, что её в сборке нет |
| `mcp issues list\|show\|url\|crashes\|sent\|delete` | черновики issue и падения инструментов; `show <id>` — markdown в stdout как есть |
| `mcp stdio` / `mcp --stdio` | мост; обе формы равноправны — клиент уже настроен как настроен |

Действие необязательно (по умолчанию `status`), хвост свободный
(`rest`): у разных действий разные аргументы, и argparse-дерево ради
одной ветки не заводилось.

## Страница MCP в веб-интерфейсе (S15)

Точка входа — `#mcp` в сайдбаре (группа «Система»). Данные страницы
отдаёт **не** `/api/mcp/info`, а `api/mcp_ui.py`.

### DNS-rebinding: белый список `Host`

Проверка `Origin` против rebinding бесполезна: имя злоумышленника,
перепривязанное на адрес роутера, даёт совпадающие `Origin` и `Host`, и
браузер считает запрос своим. При `gui.auth_enabled=false` (дефолт) это
чтение `GET /api/mcp/ui/token` и раздача разрешений со страницы
злоумышленника. Поэтому первым делом в гейте `app.py` —
`core/host_guard.host_allowed`: IP-литерал, `localhost`/`*.localhost`,
имя из `gui.allowed_hosts` (`"*"` — выключить) или хост из
`gui.cors_origins`; иначе `403`. Стоит ДО врезки MCP-токена и до
preflight — закрывает и панель, и точку, и весь остальной API.

### Почему панель — отдельная дверь, а не часть `/api/mcp`

Врезка в `app.py` (`_is_mcp_path`) пропускает валидный Bearer-токен
мимо авторизации GUI: у MCP-клиента нет ни Basic-кред, ни `Origin`.
Поддерево `/api/mcp/ui/` из неё **исключено** — иначе модель своим же
токеном включила бы себе `shell_full`. Дверь тут одна: общая
авторизация веб-интерфейса. Зафиксировано
`tests/test_mcp_ui_api.py::TestTokenDoesNotOpenThePanel`.

По той же причине страница не ходит в `/api/mcp/info`: тот роут
loopback-only, а GUI открывают из браузера на LAN-адресе. Общее тело
вынесено в `api/mcp.info_payload()` и используется обоими.

### Роуты

| Роут | Что делает |
|---|---|
| `GET /api/mcp/ui/state` | **всё состояние страницы одним ответом**: `info` (то же, что `/api/mcp/info`), `access`, `audit`, `experiment`, `code`, `shell`, `issues` |
| `POST /api/mcp/ui/enabled` | `{enabled}` — включить/выключить точку |
| `POST /api/mcp/ui/transports` | `{sse}` — legacy-SSE без перезапуска GUI |
| `POST /api/mcp/ui/token` | `{action: rotate\|clear}`; `rotate` отдаёт новый токен **один раз** |
| `GET /api/mcp/ui/token` | показать токен — по явному клику, не в общем состоянии |
| `POST /api/mcp/ui/permissions` | `{permissions: {…}}` — частичная карта, остальное сохраняется |
| `POST /api/mcp/ui/undo` | то же, что `mcp_undo_last` |
| `POST /api/mcp/ui/experiment/commit\|rollback` | решение по идущему эксперименту из GUI |
| `GET /api/mcp/ui/code/diff?snapshot_id=`, `GET …/code/patch` | дифф снимка и все локальные правки одним патчем |
| `POST /api/mcp/ui/code/commit\|rollback` | подтвердить применённую правку или вернуть файлы |
| `POST /api/mcp/ui/shell/panic` | **«запретить shell немедленно»** |
| `POST /api/mcp/ui/shell/confirm` | `{token, decision: approve\|reject}` — решение человека по команде |
| `GET /api/mcp/ui/issues/draft?id=` | черновик целиком: markdown и `open_on_github` — по клику, не в общем состоянии |
| `POST /api/mcp/ui/issues/status\|delete` | `{id, status}` — отметить отправленным; `{id}` — удалить |

Каждый мутирующий роут возвращает свежий `info`: число публикуемых
инструментов меняется в тот же запрос, без второго похода на сервер.

### «Запретить shell немедленно» — три действия, а не одно

Снять оба разрешения мало: запущенная `shell_exec_async` продолжает
работать, а невыданное решение по `confirm_token` — заряженное ружьё.
Кнопка делает всё три: гасит `shell_full` и `shell_readonly`,
`shell_exec.stop_all_jobs()` прибивает живые задачи,
`reset_confirms()` отзывает ожидания. Проверено на настоящей
`sleep 30` в `tests/test_mcp_ui_api.py::TestShellPanic`.

### Что добавлено в `core/*.py` ради страницы

| Функция | Зачем |
|---|---|
| `shell_exec.list_confirms()` | что ждёт решения человека: сводка без плана команды |
| `shell_exec.drop_confirm(token)` | «Отклонить» |
| `shell_exec.run_confirmed(record)` | исполнение подтверждённого — **одна** точка на инструмент `shell_confirm` и на кнопку GUI |
| `shell_exec.stop_all_jobs()` | аварийный запрет |
| `code_editor.pending_commit()` | применённая правка и её дедлайн одной арифметикой с `recover_after_restart` |
| `config_manager.strip_masked(data)` | маска `***` во входящем PUT заменяется текущим значением |

### Токен в UI

- в `/api/mcp/ui/state` его нет **никогда** — только `token_set`;
- `GET /api/mcp/ui/token` отдаёт значение и пишет в журнал GUI факт
  показа (без значения);
- `GET /api/config` и экспорт конфига маскируют `mcp.token` как
  `***` — раньше он уезжал открытым текстом любому, кто открыл GUI;
- сниппеты подключения содержат `<ваш-токен>`, пока человек не нажал
  «Показать».

### Правила самой страницы

- один `setTimeout`-круг (5 с), он же молчит на скрытой вкладке и
  снимается в `destroy()`;
- блоки перерисовываются **по подписи**: `_section(id, html, [signature])`.
  Без этого клик по чекбоксу отменялся бы ответом опроса;
- блоки «Эксперимент», «Правка кода» и «Shell» скрыты целиком, если
  соответствующего модуля на устройстве нет (`available: false`), а не
  показаны заглушкой;
- тексты предупреждений — в `web/js/i18n/{ru,en}.js`, ключи
  `mcp.warn.*` (токен, HTML-транспорт, ротация, перезапуск, shell,
  самоправка, аварийный запрет) и `mcp.risk.<разрешение>` (по строке на
  каждое из 12). **S16 переиспользует их в README дословно.**

## Туннели, маршруты, lua, снифер и ожидание (S17)

Сессия закрывает долги первого круга (TODO.md) и добавляет четыре
недостающих вещи. Общее у них одно: **логика живёт в `core/*.py`, а не
в `tools/`** — как `nfqws_control` у S7.

### `tunnels_write` наконец что-то открывает

Переключатель существовал с S2 и не публиковал ни одного инструмента:
модель читала `tunnels_status` и на этом останавливалась. Теперь за ним
десять инструментов, а шесть способов поднять туннель сведены в
`core/tunnels_control.py`.

Почему отдельный модуль, а не код в `tools/tunnels.py`: у sing-box и
mihomo это `up(name)`; AWG похож, но имя конфига и имя интерфейса
расходятся; usque требует СНАЧАЛА выделить интерфейс
(`iface_for_config`) и только потом `start(iface, path, sni=…,
transport_profile=…)` с профилем из настроек; Opera Proxy собирает
аргументы старта из секции конфига и после успешного старта обязана
выставить `opera_proxy.enabled` и перенастроить watchdog (иначе
автозапуск и сторож остаются мёртвыми); Telegram-прокси — это два
независимых движка под одной страницей, и имя инстанса у него
обязательно. Всё это уже было написано — внутри HTTP-обработчиков
`api/*.py`. Позвать их из MCP нельзя, повторить по памяти значит
завести вторую реализацию: «поднял из GUI» и «поднял из MCP» начали бы
значить разное (в первую очередь — переживает ли туннель перезагрузку).

`tunnel_config_get`/`_save` работают только с тремя движками
(`CONFIG_ENGINES`): у usque конфиг создаётся регистрацией устройства в
Cloudflare, у Telegram- и Opera-прокси файла нет вовсе. Конфиг
переписывается **целиком** — у трёх движков три формата (JSON, YAML,
ini-подобный `.conf`), и точечная правка каждого была бы третьей
реализацией разбора. Прежний текст уезжает в снимок
(`audit.KIND_TUNNEL_CONFIG`), откат — `mcp_undo_last`.

`pool_refresh` — единственный здесь фоновый: сборка пула ходит в
десяток источников и, при включённом health-фильтре, тестирует сотни
серверов. Она опирается на готовый `server_pool.get_refresh_job()`, а
не заводит свою очередь.

### Маршруты единого слоя (`tools/routing.py`)

Разговор с моделью почти всегда кончается вопросом «а теперь пустить
этот домен через что?». До S17 ответа не было: `tunnels_status`
показывал туннели, связать с ними домен было нечем.

Граница разрешений здесь проходит по трём уровням, и это не
формальность:

- **чтение — без разрешения.** В маршруте нет ничего секретного
  (домены, CIDR, имя интерфейса), а половина жалоб «почему не
  открывается» объясняется именно им: домен уже ведёт в погашенный
  туннель. `unified_route_status` отдельно от `unified_route_list`
  потому, что отвечает на другой вопрос: `active_method`,
  отличающийся от `method`, значит, что failover увёл трафик на
  запасной путь;
- **правка — `tunnels_write`.** Маршрут выбирает, через какой туннель
  пойдёт трафик; это ровно то, что разрешение обещает;
- **`unified_reapply_all` — `dangerous`.** Он не правит запись, а
  сносит «левые» `ip rule`/таблицы (`core/routing/sweeper`) и
  раскладывает картину маршрутов заново. На роутере, через который
  ходит и сам админ, это на секунды меняет всё сразу.

Низкоуровневых правил `core/routing` (CIDR/device/DSCP по одному) в MCP
**нет намеренно**: единый слой раскладывается в них сам, правило с
префиксом `uni-` — производное маршрута, и давать модели оба уровня
значит разрешить ей их рассогласовать.

`unified_route_save` **дочитывает непереданные поля из прежней записи**
(и только потом отдаёт их `manager.save_route`): иначе «поменяй метод»
стирало бы список доменов — маршрут сохраняется целиком.

### lua: читать, патчить, удалять

Долг S7: писать скрипт целиком модель умела, а прочитать существующий
могла только через `file_read`, то есть ценой `shell_readonly` на всю
файловую систему. Несоразмерно для «поменяй в этом скрипте одну
строку».

- `lua_script_get` без имени отдаёт **перечень** скриптов — по образцу
  `ipsets_list`: чтобы прочитать скрипт, его надо назвать, а имена
  взять было неоткуда (`lua_functions_list` перечисляет функции, а не
  файлы);
- `lua_script_patch` зовёт `code_editor.apply_edits` / `apply_unified`
  — **тот же код**, что у `code_patch`: совпадение точное и
  единственное, найденное дважды отклоняется. Второй реализации
  «замени фрагмент» в репозитории нет;
- `apply=true` перезапускает движок, но `control` спрашивается **по
  месту** (как `strategies_write` у `scan_apply`): правка скриптов и
  право дёргать движок — разные вещи. Без перезапуска правка лежит на
  диске и не действует: lua читается при СТАРТЕ, и снаружи это
  выглядит как «поправил, и ничего не изменилось»;
- `lua_script_delete` отказывается удалять bundled (они приходят с GUI)
  и перечисляет в ответе `functions_lost`: стратегия, зовущая
  пропавшую функцию, не падает — она обрывает обработку пакета.

Поле называется `is_builtin`, а не `is_bundled` (`lua_manager.
get_stats()`); в ответе инструмента оно отдаётся как `is_bundled` —
имя, которое понимает модель.

### Снифер после движка (`traffic_capture_*`)

Обратная половина `traffic_recent`: тот отвечает «дошёл ли пакет ДО
движка», этот — «что ушло в сеть ПОСЛЕ него». Раньше это стоило
`shell_full` (root) и tcpdump руками.

Рамки — в `core/traffic_capture.py`:

- **argv фиксирован.** Интерфейс проверяется по `/sys/class/net`,
  фильтр собирается ЗДЕСЬ из разобранных полей (`host`/`port`/`proto`)
  и уезжает списком, без оболочки. Произвольное BPF-выражение не
  принимается: это же и способ дописать `-z` с посторонней командой.
  `host` — только IP или подсеть: домен модель сначала разрешает
  `probe_targets`;
- потолки на число пакетов и время (`mcp.capture`, жёсткие рамки —
  константы модуля), короткий снапшот (`-s 256`: заголовки и начало
  ClientHello, а не содержимое чужих соединений), автоудаление файла;
- один прогон за раз: два tcpdump на роутере со 128 МБ кончаются не
  двумя дампами.

Разбор — `core/pcap_reader.py`, чистый модуль без единого побочного
действия (поэтому тестируется байтами, без роутера). Разбирать
**текстовый** вывод tcpdump было нельзя: формат зависит от версии и
ключей, а TTL, длины payload'а и SNI в короткой строке нет вовсе.
Понимаются три канальных уровня, которые встречаются на роутере:
Ethernet, Linux SLL (`-i any`) и RAW IP (TUN).

Сводка (`traffic_capture.summary`) считается в core, а не в
инструменте: то же понадобится UI. Смысл снифера не в списке пакетов, а
в трёх вещах, и `_capture_hint` говорит их словами: ушло ли имя
открытым текстом, разные ли TTL (значит, fake-пакеты действительно
уходят), есть ли RST.

### `job_wait` — таймер вместо опроса

Асинхронный контракт (`*_start` → `job_id` → опрашивай `*_status`)
писался под таймаут клиента и эту половину решает. Но модель не умеет
ждать: она опрашивает статус в цикле, по нескольку раз в секунду, и
трёхминутный скан превращается в полторы сотни вызовов, из которых сто
сорок девять говорят «ещё идёт» — контекст, журнал и рейт-лимит.

`job_wait` блокируется на стороне сервера до конца операции или до
бюджета (`mcp.limits.wait_sec`, потолок `max_wait_sec`) и возвращает
**ровно то, что вернул бы соответствующий `*_status`** — он его и
зовёт (`KINDS`). Второй реализации статуса нет.

Три вещи, которые легко сломать обратно:

1. **Бюджет меньше `tool_timeout_sec`** (минус `TIMEOUT_MARGIN_SEC`).
   Ожидание, которое само отваливается по таймауту, хуже опроса:
   модель не узнает ни результата, ни того, что операция идёт;
2. **Разрешение спрашивается за вид операции** (`probes` для скана,
   `experiments` для эксперимента, `shell_readonly` для фоновой
   команды). Инструмент объявлен `read`, и без этой проверки он стал
   бы дырой, через которую чтение без разрешений видит чужие
   результаты;
3. **У эксперимента признак конца — не `running`.** `awaiting_commit`
   это ТОЖЕ конец ожидания: прогон отработал и ждёт решения. Ждать его
   дальше значит проспать дедмен-свитч, по которому всё откатится.

Веб-сервер многопоточный (`app.py`, `_ThreadingWSGIServer`), поэтому
ожидание держит свой поток запроса и ничего больше.

### `mcp.transports.http` перестал быть декорацией

Долг S14: флаг висел в настройках и не влиял ни на что — хуже, чем его
отсутствие. Теперь `auth.http_enabled()` читается на каждом запросе
(как флаг SSE), и выключенный транспорт отдаёт **503 + Retry-After**,
до авторизации: для подбирающего токен это неотличимо от «точки нет», а
тому, кто выключил сам, понятно.

Отрезать себя этим нельзя: страница MCP ходит в `/api/mcp/ui/*` —
отдельную дверь под авторизацией GUI, — и включает транспорт обратно;
stdio-мост зовёт диспетчер напрямую и флагом не закрывается. Отсутствие
ключа в настройках читается как «включён»: транспорт был всегда, и
молча выключиться при обновлении GUI он не должен.

## Живой статус, память и агент (S18)

Пять вещей одной сессии, и все — поверх готового реестра: подписка на
ресурсы, снифер внутри эксперимента, память подбора, экспорт в каталог
и встроенный агент. Новых разрешений не заведено ни одного.

### `resources/subscribe`: опрос переезжает на сервер

`job_wait` — таймер: он отвечает, когда операция КОНЧИЛАСЬ. Живого
«проверено 12 из 40» он не даёт по построению, и модель возвращалась к
опросу `*_status` в цикле. Теперь у этого есть канал.

| Что | Где |
|---|---|
| Методы `resources/subscribe` / `resources/unsubscribe` | `core/mcp/server.py` |
| Подписки сессии, опрос, рассылка | `core/mcp/session.py` |
| Период опроса ресурса и его отпечаток | `core/mcp/resources.py` |
| Круг потока (`poll_resources`, `stream_wait`) | `api/mcp.py` |

Правила, которые легко сломать обратно:

* **подписка обещается только там, где её можно исполнить.**
  `capabilities.resources.subscribe` считается из `ctx`: `true` — если
  вызов пришёл по транспорту с каналом (legacy-SSE или локальный
  stdio-мост, см. «Транспорты и CLI»), иначе `false`. На
  stateless-HTTP `resources/subscribe` отвечает **отказом с адресом
  потока**, а не тихим «принято»: клиент, который подписался и не
  получает уведомлений, сломан молча;
* **уведомление шлётся от изменения, а не от круга.** Сессия хранит
  отпечаток (`resources.digest` — sha1 текста, который уехал бы
  клиенту) и сверяет его заново; совпал — молчим. Иначе подписка стоила
  бы дороже опроса;
* **период задаёт сам ресурс** (`ResourceSpec.poll`), и это **цена
  вопроса**, а не желание: `state/jobs` — 2 с (поля в памяти),
  `state/current` — 15 с (спрашивает firewall), справочники — 120 с
  (файл на 90 КБ). Опрашивать `nfqws2 -?` раз в две секунды значило бы
  запускать бинарник тридцать раз в минуту;
* **подписок не больше `MAX_SUBSCRIPTIONS` (8) на сессию**, и живут они
  ровно столько, сколько открыт поток. Брошенная подписка на роутере со
  128 МБ — такая же утечка, как брошенная сессия;
* **keep-alive не учащается вместе с опросом.** Круг генератора с
  подпиской крутится раз в 2 с, а комментарий `: keep-alive` уходит
  по-прежнему раз в `KEEPALIVE_SEC`: он нужен прокси по дороге, а не
  клиенту.

Ресурс, ради которого всё затевалось, — **`zapret://state/jobs`**:
короткая сводка по всем долгим операциям сразу. Статус берётся у тех же
getter'ов, что у `job_wait` (`jobs.KINDS`), — второй реализации
прогресса быть не должно. У фоновых команд прогон не один, поэтому
список `items` разбирается по строкам.

### Снифер внутри эксперимента

`traffic_capture_*` снимал дамп «когда-нибудь»: модель должна была
догадаться запустить его, успеть выпустить трафик и связать увиденное с
вариантом. Теперь окно дампа совпадает с окном замера по построению —
`capture: true` в `strategy_experiment_start`.

* дамп идёт **вокруг `_measure`**, то есть и на baseline, и на каждом
  варианте; между ними глушится, иначе в отчёт варианта B уехали бы
  пакеты варианта C;
* в отчёт ложится **сводка**, а не пакеты: `packets`, `ttl`, `flags`,
  `protocols`, `sni`, `iface`, `filter`. Сами пакеты по-прежнему
  читаются `traffic_capture_result(run_id=…)`;
* **дамп не ломает прогон.** Нет tcpdump, занят другой дамп, не
  разобрался файл — в отчёт уезжает строчка «почему», а замер идёт как
  шёл. Эксперимент меряет стратегию, а не снифер; `strategy_experiment_
  start` при этом говорит вслух, что снифер не включился;
* три новых правила-подсказки (`capture_ttl_too_low`, `capture_empty`,
  `capture_sni_in_clear`) — **данными**, в тот же `HINT_RULES`. Ради них
  всё и делалось: «вариант B хуже» превращается в «у варианта B fake
  ушёл с TTL 1».

### Lua-дамп движка (`lua_capture=true`, `core/lua_capture.py`)

Пара к сниферу. tcpdump стоит ПОСЛЕ движка, и пустой дамп у него не
отличает «пакет не дошёл до стратегии» от «дошёл, а приём не
справился». `pcap` из `zapret-pcap.lua` пишет то, что профиль ПОЛУЧИЛ
из очереди, — и разница становится видна.

* **`--writable` выдаёт `NFQWSManager.compose_command`** — любой
  стратегии, где есть инстанс `pcap`. Свой `--writable` стратегии не
  положен и вырезается (см. «Аргументы стратегии: чем владеет GUI»):
  nfqws2 делает `chown` названного каталога от root, и существующего
  тоже. Каталог — `lua_capture.writable_dir()`
  (`/tmp/zapret-gui-writable`, tmpfs: дамп нужен на минуту); `start()`
  готовит его заранее (`prepare_dir`): `/tmp` открыт всем, и симлинк
  на месте каталога движок иначе прошёл бы своим `chown`. Без флага
  `pcap` с относительным именем пишет в cwd процесса, куда под
  `nobody` нельзя, и обработка пакета обрывается ошибкой lua;
* **`pcap` встаёт перед ПЕРВЫМ `--lua-desync` профиля** (`inject`).
  `--payload`/`--out-range`/`--in-range` действуют на все следующие
  инстансы: поставь мы его раньше со своими диапазонами — их
  унаследовали бы приёмы, и мерили бы мы уже не стратегию модели.
  Профиль без приёмов пропускается (пакеты идут мимо lua), свой `pcap`
  в стратегии не дублируется;
* пишется `raw_packet(ctx)` — пакет, каким его отдала очередь, а не
  результат десинка (тот уходит `rawsend`'ом мимо инстансов). «Что
  отправил» по-прежнему видно только tcpdump'ом;
* **в движок уходит argv с `pcap`, в отчёт и в commit — без него**:
  это прибор, а не часть стратегии (`out["args"]` — исходные);
* разбор — `pcap_reader` (формат `zapret-pcap.lua`: big-endian,
  наносекунды, raw IP), сводка — `pcap_reader.summarize()`, та же, что
  у tcpdump, плюс `profiles` (сколько пакетов получил каждый профиль —
  это ответ, какой фильтр не сработал). Файлы удаляются сразу, читаем
  не больше `MAX_FILE_BYTES`;
* правило-подсказка `lua_capture_empty`: движок поднят, пробы прошли,
  а дамп пуст → чинить фильтр профиля и правила NFQUEUE, а не приём;
* нет `zapret-pcap.lua` — `available: false` и строчка в `hint`
  ответа `strategy_experiment_start`, прогон идёт без дампа.

### Память подбора (`core/strategy_memory.py`)

Отчёты эксперимента живут в памяти процесса и умирают вместе с ним —
поэтому каждая следующая модель начинала с нуля. Теперь движок сам
складывает выводы в файл рядом с `settings.json`.

* запись — тройка **«сеть, домен, argv»** плюс счётчики `wins`/`losses`
  и `last_seen`;
* запоминается **вклад, а не успех**: цель, открытая и БЕЗ обхода, в
  память не попадает вовсе, а прогон без baseline не пишется совсем.
  Иначе «лучшим» назавтра оказался бы вариант, который ничего не делает;
* **метка сети считается локально** (`network_key`): интерфейс default
  route, шлюз и блок /16 своего WAN-адреса. В интернет за ней никто не
  ходит — это и лишний след, и зависимость от чужого сервиса. Поле
  называется `id`, а не `key`: маска секретов режет значения под ключами
  вида `*key*`, и метка уехала бы модели как `***`;
* чужая сеть не выбрасывается, но и не смешивается: `other_networks`,
  и только по явному `all_networks=true`;
* `commit` не добавляет наблюдение, а ставит флаг (`mark_committed`):
  иначе один прогон посчитался бы дважды;
* наружу — инструмент `strategy_memory` и ресурс
  `zapret://memory/strategies` (зеркало, как у всех справочников).

Запись в память **никогда не роняет прогон**: обе точки вызова в
`strategy_experiment` обёрнуты и логируют отказ в debug.

### Экспорт в каталог (`core/catalog_export.py`)

Каталоги приезжают сверху (сборка GUI), а находки появляются снизу.
`strategy_export_catalog` собирает из argv готовую секцию INI.

* **проверка round-trip обязательна**: собранная секция тут же читается
  `catalog_loader._parse_catalog_content`, и если argv не совпал
  дословно — отказ. Формат мягкий: строка без `--` читается как
  метаданные, перевод строки в описании режет секцию пополам, и оба
  случая происходят молча;
* **файлов не пишет.** `catalogs/` перезаписывает установщик
  (`core/asset_importer.py`), и локальная правка там потерялась бы при
  первом же обновлении. Наружу уезжает текст — дальше он едет в git;
* поэтому инструмент объявлен `mutating=False` при scope
  `strategies_write` — как `strategy_compose`/`strategy_validate`
  (разрешение не про «мы пишем», а про то, что собранное предназначено
  для записи);
* уровень и протокол выводятся из argv (`--filter-*`/`--new` → это
  полная конфигурация, то есть `builtin`), метки сверяются с
  `_VALID_LABELS` загрузчика — сторожем, а не на глаз.

### Встроенный агент (`core/agent_runner.py`, `core/llm_client.py`)

Та же модель, что ходит по MCP, но локально и кнопкой:
`api/agent.py` + `web/js/pages/agent.js`, флаг `agent.enabled`.

* **новых возможностей нет.** Агент — это цикл: спросил модель → она
  попросила инструмент → позвали `registry.call` → отдали результат.
  Разрешения, маскировка, журнал, лимиты ответа — то же самое и в том
  же месте;
* **своих разрешений нет и не будет.** Набор инструментов —
  `registry.available_tools(permissions.current())`;
* **отдельная дверь.** Выключенный `mcp.transports.http` агента не
  выключает, выключенный `agent.enabled` не трогает MCP. Роуты
  `/api/agent/*` живут под общей авторизацией GUI: врезка «MCP со своим
  токеном мимо гейта» действует только на `/api/mcp` — и это намеренно,
  здесь дают инструментам исполняться;
* **инструментов столько, сколько модель осилит.** 118 объявлений — это
  больше пятнадцати тысяч токенов в каждом запросе. По умолчанию
  (`agent.tools = scenarios`) отдаются инструменты готовых сценариев
  (`prompts.tool_names()`) плюс `BASE_TOOLS` — около тридцати;
* **готовые задачи — те же сценарии** (`prompts.get_prompt`), а не
  вторая копия порядка действий;
* потолки: `max_steps` (12), `HARD_MAX_TOOL_CALLS` (80),
  `tool_result_chars` (6000 — реестр режет по `response_kb`, но там
  потолок рассчитан на Claude, а не на локальную 8B), стоп-флаг между
  шагами;
* `core/llm_client.py` — сорок строк `urllib`: ни `openai`, ни
  `requests` на роутер не едут. К **локальным** адресам ходим мимо
  прокси окружения: `HTTPS_PROXY` на роутере настроен на обход
  блокировок, и запрос к `127.0.0.1` через него не пройдёт никогда.

## Ошибки самого GUI: падения и черновики issue

Модель, работающая с роутером, первой видит, что инструмент упал или
ответил не по описанию. Раньше от этого оставалась строка
`TypeError: …` без файла и номера: трассировка писалась в лог уровнем
`debug` и пропадала. Теперь два модуля, и оба **не падают сами**.

### Журнал падений (`core/mcp/crashes.py`)

`registry.call` в ветке `except` зовёт `crashes.capture(tool, exc,
args=, handler=)`; запись — строка в `mcp-crashes.jsonl` рядом с
`settings.json` (ротация до `KEEP` = 30), `crash_id` уходит в ответ
модели вместе с `where` (`файл:строка` верхнего кадра) и `hint` про
`issue_draft`, и в журнал вызовов через `audit.note(crash_id=…)`.

| Поле | Что в нём |
|---|---|
| `frames` | кадры **только проекта**: путь относительно корня, строка, функция, текст строки. Без `vendor/`, stdlib и кадра `registry.call` (он есть в каждой трассировке). Нет ни одного проектного — хвост как есть |
| `handler` | `crashes.locate(spec.handler)`: файл и первая строка обработчика |
| `args` | `audit._safe_args` — та же двойная маска, что у журнала |
| `fingerprint` | sha1 от инструмента, типа исключения, файла и **функции** верхнего кадра — без номера строки: он сдвигается от любой правки выше |
| `local_code_changes` | правки самоправки (S13): номера строк им не верны, и это сказано в самой записи |

Корень проекта — по `__file__`, а не `code_editor.project_root()`: та
читает настройки, а модулю, который зовут из обработчика ошибки,
нельзя тянуть то, что может упасть. Кадр файла, которого нет на диске
(`<string>`, `<stdin>`), проектным не считается.

### Черновики issue (`core/mcp/issues.py`, `tools/issues.py`)

Черновик собирают двое. Модель пишет то, что видела (`title`, `kind`,
`actual`, `expected`, `steps`, `evidence`); сервер
(`collect_context`) — то, что модель исказила бы: обработчик и
трассировку, `repro` (аргументы последнего вызова из журнала, если не
переданы явно), окружение **без hostname и WAN-адреса**, действующие
разрешения, версии движков **из кеша** (в сеть не ходим), последние
вызовы и строки лога warning+ за 10 минут.

* **Не мутирующий и без разрешения.** Устройство черновик не меняет:
  он ложится в собственный файл GUI (`mcp-issue-drafts.json`), как
  журнал. Держать его за разрешением значило бы, что модель,
  нашедшая ошибку при чтении, промолчит о ней. Против спама —
  `MAX_DRAFTS` = 30 (первыми уходят отправленные) и склейка повторов.
* **Склейка по отпечатку.** У падения — `crash:` + отпечаток
  трассировки, у остального — `text:` + вид, инструмент, компонент и
  нормализованный заголовок. Повтор увеличивает `occurrences`,
  дописывает `crash_ids` и дозаполняет пустые поля; склеивается только
  со статусом `draft` — отправленный уже на GitHub.
* **Наружу не уходит без человека.** GitHub-токена на роутере нет:
  страница MCP и `mcp issues url` дают ссылку `/issues/new?title=…&body=…
  &labels=from-agent`, и issue открывает человек своим аккаунтом.
  Ссылка длиннее `MAX_URL` (7500) — сначала компактный текст (без
  журнала и лога, три кадра), потом заглушка «вставьте из буфера»;
  страница тогда копирует полный текст сама (`body_shortened`).
* **Домены и публичные адреса маскируются при РЕНДЕРЕ** (`_Masker`,
  одна метка на значение во всём черновике). Хранится исходный текст
  (после `redact_text`) — маска зависит от `include_targets`, а файл
  лежит на самом роутере. Не маскируются: частные адреса, имена файлов
  (окончание из `_FILE_SUFFIXES`), имена из кода (`_looks_like_code`:
  CamelCase в последней метке — `urllib.error.URLError`; путь модуля с
  `_MODULE_HEADS`, **если окончание не похоже на зону** — двухбуквенную
  или из `_COMMON_TLDS`: `api.telegram.org` и `web.whatsapp.com` — домены,
  а не наши пакеты `api`/`web`), адреса апстримов (`_KEEP_DOMAINS`).
  Сомнение — в пользу маски. Метки в `repro` делают команду
  невоспроизводимой — рядом с ней строка «замените метки». Аргументы
  `repro`, переданные моделью, маскируются по ключам (`audit._safe_args`)
  ещё при сохранении — как в журнале.
* **Машиночитаемый блок** (`machine_block`, схема
  `zapret-gui-report/v1`) в конце тела — для разбора отчёта: инструмент,
  обработчик, кадры `файл:строка:функция`, `repro`, версия, отпечаток.

Ключ ссылки в ответе — `open_on_github`, **не** `github_url`: всё, что
кончается на `_url`/`_link`, маска режет до хоста (`URL_KEY_RE`), и
модель получила бы обрубок.

### Как разбирать такое issue

1. Команда из «Как воспроизвести» — `zapret-gui mcp call …` на
   устройстве или `registry.call(...)` в тесте (метки `<домен-N>`
   заменить любым доменом).
2. Место — `frames` машиночитаемого блока (последний — где упало) и
   `handler`; при `local_code_changes` > 0 номера строк сверять с
   патчем устройства (`code_export_patch`), а не с релизом.
3. `kind: contract`/`docs_mismatch` — сверить описание инструмента
   (`description` в `@tool`) и этот скил с ответом: чинится то, что
   неправо, а не всегда код.

## Секреты

`redact.redact(payload)` зовётся один раз — в `tool_result()`. Маскируем
**по ключам**, а не по значениям:

- ключ подходит под `SECRET_KEY_RE` (`pass|secret|token|key|licen|uuid|auth|
  credential`) → строка/словарь/список → `"***"`; булевы и числа остаются
  (ответ из одних `***` модель прочитать не может);
- ключи-URL (`URL_KEY_RE`) → `https://host/…`;
- строки под `TEXT_KEYS` (`stdout`, `stderr`, `message`, `command`…)
  дополнительно чистятся `redact_text()` — по маркерам `token=`,
  `Authorization:`, `PrivateKey =`, `user:pass@host`;
- домены, hostlist'ы, аргументы стратегий и lua **не трогаем** — это рабочие
  данные модели.

S12/S13 (shell, самоправка) отдают сырой текст: кладите его под ключ из
`TEXT_KEYS` или зовите `redact.redact_text()` явно.

## Документация: кто что говорит (S16)

Четыре текста про одно и то же — и у каждого своя работа. Путать их
дорого: README, написанный как спека, никто не прочитает, а скил,
написанный как README, перестанет быть источником сигнатур.

| Файл | Для кого | Отвечает на вопрос |
|---|---|---|
| `README.md`, раздел «Управление через ИИ (MCP)» | пользователь роутера | зачем это нужно, как включить, как подключить клиента, **чем я рискую** |
| `.claude/skills/mcp/SKILL.md` (этот файл) | тот, кто правит код | как устроено, точные сигнатуры, границы, грабли |
| `CoderManual.md` §5.1, §6, §13 | тот, кто добавляет свой инструмент | куда класть файл и что ещё обновить |
| `docs/mcp/*` | архив | как фича делалась, сессия за сессией; см. `docs/mcp/README.md` |

Правила, которые легко нарушить:

- **README называет каждый инструмент.** Не потому что пользователю
  нужны 118 имён, а потому что он решает, какие разрешения включать, —
  и должен видеть, что именно открывает каждое из них. Группировка в
  README идёт **по разрешению**, а не по домену;
- **тексты предупреждений — из одного места.** `mcp.warn.*` и
  `mcp.risk.*` в `web/js/i18n/{ru,en}.js` показывает страница, README
  повторяет их смысл. Меняете формулировку риска — меняйте в i18n, и
  пусть README следует за ней, а не наоборот;
- **«включите HTTPS» писать нельзя** — своего TLS у GUI нет. Честные
  пути: `bind = local` + ssh-туннель, stdio-мост, обратный прокси;
- **у каждого переключателя есть что открыть — кроме `secrets`.** До
  S17 так висел `tunnels_write` (теперь за ним десять инструментов);
  `secrets` своих инструментов не имеет намеренно, и README с этой
  таблицей обязаны говорить это прямо: молча висящий переключатель
  выглядит как сломанная фича;
- **`docs/upstream.json` → `mcp-spec`.** `pinned` — не версия чужого
  кода, а **ревизия спеки** (`server.PROTOCOL_VERSION`). `paths` и
  `content_checks` стерегут, что папка спеки с этим именем ещё
  существует и внутри неё всё ещё та ревизия. Выход новой ревизии — это
  не «обновить число»: старые остаются в `SUPPORTED_PROTOCOL_VERSIONS`,
  потому что клиенты переходят не все.

## Тесты-сторожа

| Файл | Что стережёт | Когда обновлять |
|---|---|---|
| `tests/test_mcp_tool_counts.py` | сколько инструментов открывает каждое разрешение (`BY_SCOPE`) | **каждая сессия**, добавляя свои |
| `tests/test_mcp_tools_docs.py` | реестр не разошёлся с документацией: у каждого инструмента есть строка в ЭТОЙ таблице (с верными scope/mutating/файлом) и имя в README | не трогать — он перебирает реестр сам |
| `tests/test_mcp_redaction.py` | ни один read-only инструмент не отдаёт секрет; перебирает реестр сам | не трогать — он находит новое сам |
| `tests/test_mcp_writable_paths.py` | каждый ключ `DEFAULT_CONFIG` отнесён к writable/не-writable осознанно | при добавлении настроек |
| `tests/test_mcp_schema.py` | объявления инструментов: имя, описание, scope/mutating, схема | не трогать |
| `tests/test_mcp_permissions.py` | `tools/list` следует переключателям; вызов по имени в обход списка отклоняется | при новых зависимостях |
| `tests/test_mcp_tools.py` | форма ответа четырёх эталонных инструментов | при правке эталона |
| `tests/test_mcp_resources.py` | `resources/*`, пагинация, «нет бинаря» ≠ падение | при новом ресурсе |
| `tests/test_mcp_resources_mirror.py` | ресурс = `docs_get` дословно; writable-путь без описания | при новом ресурсе или настройке |
| `tests/test_mcp_prompts.py` | промт не обещает несуществующий инструмент | при новом промте |
| `tests/test_mcp_tools_nfqws.py` | инструменты S4: общая форма списка (перебором), пагинация, фильтры, «менеджера нет» ≠ падение, размер ответа | при новом списочном инструменте |
| `tests/test_mcp_tools_tunnels.py` | форма записи движка, «не установлен» ≠ ошибка, упавший движок не роняет сводку, ключи пиров не уезжают | при новом движке или поле записи |
| `tests/test_mcp_tools_diagnostics.py` | граница «читает/пробует»: без `probes` ни одной пробы, с ним — полный прогон; бюджет времени; `dpi_report` ничего не запускает | при новом инструменте с частичными пробами |
| `tests/test_mcp_config_write.py` | запись вне whitelist'а, deny-поле, несуществующий путь, тип, `enum`, дифф в ответе, список заменяется целиком | при правке границы записи |
| `tests/test_mcp_audit.py` | снимок на мутацию, откат (в т.ч. после «перезапуска» — другим процессом), ротация не уносит снимок, отклонённый вызов = warning, токен не в журнале | при новом виде снимка (`kind`) |
| `tests/test_mcp_control.py` | без `control` инструментов нет ни в списке, ни по имени; неудачный старт СНИМАЕТ правила; занятый сканером движок не трогаем; SIGHUP ≠ перезапуск; «менеджера нет» ≠ трассировка | при новом инструменте `control` |
| `tests/test_mcp_strategies_write.py` | CRUD user-стратегий, builtin неприкосновенна, `../` в id, лимит размера, снимок и откат по шагам; **приёмка S7**: цикл `save → apply → restart → undo → undo` на `control`+`strategies_write` без `config_write` | при правке формата стратегии |
| `tests/test_mcp_lists_write.py` | режимы `replace/add/remove`, пустой hostlist = предупреждение, непринятые записи, лимиты, `reloaded`, откат для списков/blob/lua | при новом write-инструменте списков |
| `tests/test_mcp_firewall.py` | порты управления не доезжают до правил — и через обёртку MCP, и через сам `apply_rules`; диапазон режется, а не выбрасывается; «остались только порты управления» = правила не ставятся вовсе | при правке состава правил |
| `tests/test_mcp_probes.py` | коды только из `PROBE_CODES`, все пять вердиктов `probe_compare`, движок возвращается на место (в т.ч. после упавшей пробы), лимит целей и повторы по большинству, `connectivity_matrix` без `probes` ничего не прогоняет | при новом инструменте проб или новом вердикте |
| `tests/test_mcp_jobs.py` | асинхронный контракт: `*_start` отдаёт `job_id` сразу, `*_output` инкрементален по `offset`, второй старт при занятом движке называет активный `job_id`, завершённая задача продолжает отвечать | при новом виде задачи (`_jobs.KIND_*`) |
| `tests/test_nfqws_session.py` | общий мьютекс: отказ называет владельца и время, лок не залипает (исключение, повторный `release`, мёртвый/протухший lock-файл), `restore` идемпотентен, `apply_temporary` без захвата отказывает, сканер и `nfqws_control` ходят через сессию | при новом владельце или поле снимка |
| `tests/test_mcp_experiment.py` | полный цикл: снимок → варианты → возврат; **авто-откат по TTL** и `keep_best` ≠ `commit`; `commit`/`rollback`/`stop`; отказ при занятом сканером движке; «цель открыта и без обхода» → нет победителя; отчёт влезает в `limits.response_kb`; медиана по `repeats`; снимок на диске и `recover_after_restart` | при новом поле отчёта или новом решении |
| `tests/test_mcp_hints.py` | правила-подсказки: эталонные строки лога дают ожидаемые id, все подстроки — в ОДНОЙ строке, у каждого правила есть `ref`, у метрического — предикат | при новом правиле (S11) |
| `tests/test_mcp_shell.py` | safe-список работает и ограничивает; `sh -c` под `shell_readonly` отклонён; таймаут прибивает; обрезка сохраняет хвост; `env` без переменных GUI; `stdin` закрыт; фоновая задача отдаёт `job_id` и стримит вывод | при новой команде в safe-списке |
| `tests/test_mcp_shell_guards.py` | `DENY_RULES` не обходятся (кавычки, `env`, `/bin/`, `\`, `;`) и не ловят лишнего; токен одноразовый и протухает; подтверждение прав не выдаёт; сетевая команда без `guard` не выполняется; дедмен срабатывает, срабатывает один раз и переживает перезапуск GUI | при новом правиле запрета/подтверждения |
| `tests/test_mcp_shell_redaction.py` | вывод `cat` конфига с паролем и ключом приходит замаскированным — и в ответе, и в журнале; рабочие данные (адреса, параметры) целы; `confirm_token` НЕ маскируется | при новом маркере в `redact_text` |
| `tests/test_mcp_files.py` | запись вне `allow_write_paths` и по симлинку наружу отклонена; файлы GUI защищены; права переживают запись; снимок и откат (в т.ч. «файла не было» → удалить); слишком большой для бэкапа файл не перезаписывается | при правке границы записи файлов |
| `tests/test_mcp_system_tools.py` | пакеты и службы на НАСТОЯЩИХ скриптах-подменах: разбор `opkg list-installed`, имя пакета не доезжает до менеджера, удаление через подтверждение, откат установки; имя службы сверяется со списком на диске, `status` по `shell_readonly`, `restart` — нет, `stop` обратим | при новом действии со службой или пакетом |
| `tests/test_mcp_transport.py` | HTTP-слой: 405 с объяснением, битый заголовок = 4xx не 500; **legacy-SSE**: `event: endpoint` первым, ответ приезжает в поток, `202` на `/messages`, лимит `max_sessions`, разрыв клиента чистит сессию, уборка молчащих, рассылка `tools/list_changed`, переключение SSE без перезапуска | при правке транспорта |
| `tests/test_mcp_stdio.py` | мост: построчно, батч, мусор → `-32700` и мост жив, EOF завершает, в stdout только JSON, служебное в stderr, прокси-режим и его отказы; **поток-писатель**: подписка и `tools/list_changed` приходят, пока stdin молчит, записи не перемешиваются, EOF гасит писателя | при правке моста |
| `tests/test_mcp_cli.py` | `status`/`tools`/`call` на подменённом реестре, `token rotate` пишет токен на диск и предупреждает, неверный JSON объясняется, `mcp code` без S13 говорит честно | при новой подкоманде |
| `tests/test_mcp_ui_api.py` | роуты страницы: число инструментов следует галочкам, «запретить shell немедленно» гасит переключатели И прибивает живую задачу, MCP-токен НЕ открывает панель разрешений, `/api/config` не отдаёт токен | при новом роуте панели |
| `tests/test_mcp_page.js` | сама страница в `node:vm` поверх мини-DOM: `render`/`destroy`, одно состояние одним запросом, токен точками, скрытые блоки 6–8, предупреждения из i18n, `mcpServers` без поля `type`, у каждого из `PERMISSIONS` есть переключатель (`PERM_ORDER` ведётся руками — `secrets` из него однажды выпал) | при правке разметки страницы или новом разрешении |
| `tests/test_mcp_subscribe.py` | подписка (S18): на stateless-HTTP `subscribe: false` и отказ с адресом потока; уведомление приходит ОТ ИЗМЕНЕНИЯ, а не на каждом круге; лимит подписок; закрытый поток их забывает | при новом ресурсе с быстрым опросом |
| `tests/test_lua_capture.py` | `--writable` только при `pcap` и не поверх своего; `pcap` перед первым приёмом профиля, argv иначе не меняется; формат `zapret-pcap.lua` читается, файлы удаляются; в эксперименте `pcap` уходит в движок, но не в отчёт, пустой дамп → `lua_capture_empty` | при правке места вставки или формата дампа |
| `tests/test_strategy_memory.py` | память подбора: вклад, а не успех (открытое и без обхода не пишется); прогон без baseline не пишется вовсе; сети не смешиваются; битый файл = пустая база | при правке формата записи |
| `tests/test_catalog_export.py` | экспорт в каталог: round-trip через наш парсер, отказ на аргументе без `--` и на переводе строки в метаданных, метки совпадают с `_VALID_LABELS`, файлы `catalogs/` не трогаются | при правке формата INI |
| `tests/test_agent_runner.py` | агент: выключенный не ходит никуда; цикл «модель → инструмент → модель»; неизвестное имя инструмента — ответ, а не падение; `max_steps` и стоп-кнопка; набор инструментов следует разрешениям | при правке цикла |
| `tests/test_api_agent.py` | роуты страницы «Агент»: ключ не уезжает наружу, пустое поле = «не менять», состояние одним ответом | при новом роуте |
| `tests/test_mcp_issues.py` | падение инструмента даёт `crash_id` и кадры проекта (без кадра реестра), секреты не попадают ни в журнал падений, ни в черновик; черновик несёт обработчик и `repro`; повторы склеиваются; домены и публичные IP замаскированы, частные и имена файлов — нет; ссылка укладывается в длину; `open_on_github` не режется маской; потолок черновиков | при правке формы записи или черновика |
| `tests/test_mcp_hardening.py` | находки ревью: сравнение секрета по байтам (кириллица, мусор в заголовке), короткий ответ «слишком много», NaN/`True` в схеме и копия `default`, маска JSON/YAML/прокси-ссылок, отказ записать маску обратно, опции движка в стратегии, `file_write` по проверенному пути и FIFO в `file_read`, `snapshot_id` с `../` | **не ослаблять**: каждое правило — закрытая дыра |
| `tests/test_mcp_no_dangerous.py` | инструмента `teardown` (и родни) нет; под `dangerous` ровно один инструмент; `system_reboot` не выполняется одним вызовом, токен прав не даёт, `shell_full` не открывает чужих инструментов | **никогда не ослаблять** |

Прогон: `python3 -m unittest discover -s tests -p "test_mcp_*.py"`; полный —
`python3 -m unittest discover -s tests -t .`.
JS-тесты страницы — `node --test tests/test_mcp_page.js` (npm-зависимостей
у них нет).

## Грабли

- **`hmac.compare_digest` на str принимает только ASCII.** На
  кириллическом пароле GUI или на U+FFFD из битого `Authorization` он
  бросает `TypeError` — 500 вместо 401, а allow_gui_auth с русским
  паролем не пускал никогда. Сравнение секрета — только
  `auth.secret_equal` (по байтам), и в `app.py` тоже.
- **Маска по ключам не видит ключей внутри текста.** `cat settings.json`
  — это строка, а не dict: `"token": "…"` проходил `redact_text`
  насквозь (правила ждали `token=`/`token:` без кавычки). Для текста
  есть `_JSON_PAIR_RE`/`_YAML_PAIR_RE`, и имя ключа они проверяют ТЕМ
  ЖЕ `_is_secret_key`, что структурная маска.
- **Ответ «слишком много» — тоже ответ, и он обязан быть коротким.**
  `_truncated` сохранял скаляры верхнего уровня «как заведомо
  короткие», а длинная строка (текст конфига, файла) и есть то, из-за
  чего ответ не влез. Строки длиннее `TRUNCATED_STR_MAX` выкидываются
  и перечисляются в `dropped_fields`.
- **Маску, записанную обратно, не остановит подсказка.** Модель
  читает `***`, правит соседнюю строку и сохраняет текст целиком.
  Пишущие инструменты спрашивают `redact.mask_written_back()` и
  отказывают (`MASK_WRITE_HINT` — куда идти за `raw=true`).
- **`os.replace` подменяет симлинк, а не его цель.** Граница, проверенная
  по `realpath`, и место записи расходились: ссылка вне разрешённых
  каталогов на файл внутри них становилась записью вне их. `file_write`
  пишет по резолвнутому пути.
- **Идентификатор снимка — тоже путь.** `snapshot_path` сверяет id с
  `_ID_RE` всегда: `../` делал чужой `manifest.json` снимком со своим
  `root`, и `code_rollback` восстанавливал по нему что угодно, включая
  защищённое ядро.

- **Ключ `*_url` в ответе маска режет до хоста.** `github_url` с
  готовой ссылкой на новое issue доезжал до модели как
  `https://github.com/…` — без тела и заголовка. Поле называется
  `open_on_github`; то же касается любого поля, которое обязано дойти
  адресом целиком.
- **`confirm_token` маскировался как секрет.** Слово `token` подходит
  под `SECRET_KEY_RE`, и двухшаговое подтверждение не работало в
  принципе: модель получала `***`. Исключение — точечное
  (`redact.PUBLIC_KEYS`), а не ослабление регулярки.
- **`from core import X` берёт АТРИБУТ пакета, а не `sys.modules`.**
  Тест, подменявший `core.system_control` через `mock.patch.dict
  ("sys.modules", …)`, в одиночку проходил, а в общем прогоне звал
  настоящий `reboot`: соседний тест успел импортировать модуль, и
  атрибут у пакета уже был. Подменять надо функции модуля
  (`mock.patch.object`).
- **`stream.read(n)` у буферизованного потока ЖДЁТ `n` байт.** Вывод
  фоновой команды появлялся у модели только после её завершения — то
  есть инкрементального чтения не было вовсе. Нужен `read1()`.
- **Нормализация команды обязана идти ДО матчинга запретов.** `env  rm
  -rf /`, `"rm" -rf /`, `/bin/rm -rf /`, `r\m -rf /` — четыре способа
  обойти наивное сравнение строк, и они все в тесте.
- **`env` как команда нормализуется в пустоту.** `env` — префиксное
  слово, и после его снятия от argv ничего не остаётся. Пустой
  нормализованный argv откатывается к исходному (и упирается в
  safe-список), иначе отказ читался бы как «команда состоит из одних
  префиксов».
- **Дедмен, живущий только в памяти, не откатывает ничего.** Таймер
  умирает вместе с процессом, который и уронил связь. Запись — на
  диск, восстановление — при старте GUI.
- **`-32601` на `resources/*` и `prompts/*` — сломанное подключение, а не
  «пока не сделано».** Клиенты опрашивают их сразу после `initialize`.
- **Сессию SSE нельзя заводить внутри генератора.** После первого
  `yield` заголовки уже ушли клиенту, и отказать `429`-м на превышение
  `max_sessions` нечем. Заводит обработчик, генератор только получает
  готовую.
- **Мёртвая SSE-сессия — это утечка, а не мелочь.** Сто сообщений в
  очереди брошенного клиента на роутере со 128 МБ дают о себе знать не
  сразу, а через сутки. Живость — по ходу самого потока (`touch()` на
  круге), не по времени последнего запроса: клиент имеет право молчать.
- **Тест SSE не может читать тело целиком.** `WSGIClient` дочитывает
  ответ до конца, а поток не кончается никогда. В
  `tests/test_mcp_transport.py` для этого свой `_Stream`: вызывает
  приложение сам и тянет события по одному. Он же и есть настоящий
  клиент по поведению.
- **Перевод строки внутри `data:` разрывает SSE-событие надвое.**
  Ответ сериализуется без `indent`, но `_sse_event` всё равно вычищает
  `\r`/`\n`: один `default=str` над объектом с переносами — и клиент
  получает полсобытия.
- **`from core import X` в CLI не ловит отсутствие модуля.** `mcp code`
  проверяет наличие самоправки через `importlib.import_module`: у
  пакета `core` атрибут `code_editor` остаётся от чужого импорта, и
  `from core import code_editor` отработает даже там, где файла нет.
- **Реестр глобальный.** Тест, регистрирующий свой инструмент, обязан убрать
  его в `finally` — и **только если сам добавил** (иначе вынесет настоящий).
- **Не называйте поля со словом `key` — и со словом `auth`.** `_keys`,
  `by_key`, `author` уезжают модели как `"***"`: маскировка смотрит на имя
  ключа и не знает, что поле ваше. Отсюда `_fields` в `config_get`, `group`
  вместо `key` в `strategy_state_list` и `made_by` вместо `author` в
  каталогах. Полный список масок — `redact.SECRET_KEY_RE`; ослаблять его
  ради красивого имени поля нельзя, переименовывается поле.
- **Фабрика менеджера — внутри `try`, а не перед ним.** На устройстве без
  zapret2 падает сама `get_*_manager()`, и инструмент, обернувший только
  вызов метода, всё равно отдаёт трассировку вместо ответа — ровно там, где
  он нужнее всего.
- **`cfg.get()` — это не `effective()`.** `get()` отдаёт только то, что
  записано в `settings.json`; у «холодного» менеджера (MCP, CLI) порты и
  путь к бинарнику оттуда приезжают как `None`. Дефолты живут в
  `effective()`.
- **`limit=100` не значит «влезет 100».** Сотня записей каталога — 40 КБ при
  лимите 32; без ужимания в `_paging.page()` модель получила бы вместо
  страницы «ответ слишком большой».
- **Метку времени отдавайте без округления.** Модель возвращает `ts` в
  `since`, чтобы дочитать хвост: округление вниз повторяет последнюю запись,
  вверх — теряет соседнюю.
- **Импорты менеджеров — внутри обработчика.** Реестр грузится при первом
  запросе; тяжёлые импорты на уровне модуля стоят заметного времени на
  роутере, а недоступный менеджер ломал бы весь реестр.
- **Инструменты не публикуются «частично».** Если часть действий читает, а
  часть пробует — публикуем всегда, проверяем действия по отдельности.
- **`bool` — подтип `int`.** Валидатор намеренно не пропускает `True` как
  `integer`/`number`.
- **`restore()` не сверяет argv.** Он идемпотентен по состоянию: движок
  запущен и снимок говорит «запущен» — шага нет, аргументы никто не
  сравнивает. Кто применял ЧУЖОЙ argv, обязан погасить движок сам перед
  возвратом (`strategy_experiment._stop_engine`), иначе временная
  стратегия остаётся на роутере, а лог рапортует «состояние
  восстановлено».
- **Захват мьютекса потоко-привязан.** Взять его в одном потоке, а
  трогать движок из другого нельзя: `apply_temporary` бросит, а
  `nfqws_control` ответит `SessionBusy`. Всё, что делается под захватом,
  делает тот же поток, который захватывал.
- **Синглтон движка экспериментов общий на процесс.** Тест, гонявший
  прогон, обязан вернуть его чистым (`strategy_experiment._runner =
  None`) — иначе «прошлый прогон» протекает в соседний тест.
- **Плоский ответ теряет имя ключа, по которому работает маскировка.**
  `config_describe(path="gui.auth_password")` отдавал пароль в поле
  `value`: `redact` смотрит на имя ключа, а оно осталось в `path`.
  Разворачиваете путь в плоские поля — маскируйте сами
  (`redact.is_secret_key(parts[-1])`).
- **Живой ресурс нельзя сравнивать дословно.** `zapret://state/current`
  меняется между двумя чтениями (свободная память, аптайм): зеркало для
  него — совпадение набора полей. Список таких — `resources.VOLATILE`.
- **Карта lua-функций собирается разбором скриптов, а не списком в коде.**
  Формат шапки задан апстримом (`-- nfqws1 :`, `-- standard args :`,
  `-- arg :` над `function имя(ctx, desync)`); список в коде разошёлся бы
  с bundle в первый же апстрим.
- **Справка `nfqws2 -?` кешируется по файлу, а не по пути.** После
  обновления zapret2 путь тот же, а справка другая — ключ кеша включает
  размер и mtime.
- **Собственную подсказку к странице — ДОПИСЫВАТЬ, а не записывать.**
  `page()` объясняет в `hint`, что окно ужато под лимит ответа;
  `result["hint"] = ...` затирает это объяснение, и модель получает
  пустой список без единого слова почему.
- **`allowed(scope)` без `perms` — это «запрещено всё».** `normalize
  (None)` отдаёт карту из одних `False`. Инструменту, спрашивающему
  разрешение по месту, нужен `permissions.granted(name)`.
- **Секрет приезжает и под несекретным именем ключа.** Строка лога
  движка (`last_error`), сообщение упавшего вызова (`error`), cmdline
  чужого процесса (`detail`) — текст ИЗ ВНЕШНЕГО МИРА, и в нём бывает
  `token=`. Такие ключи добавлены в `redact.TEXT_KEYS`; кладёте сырой
  текст под новым именем — добавьте и его.
- **`tg://proxy?…secret=` — тоже адрес.** `shorten_url` работала только
  с `http(s)://`, а ссылку Telegram-прокси пропускала целиком. Теперь
  не-HTTP адрес под URL-ключом уходит в `redact_text`. Сам
  `get_connect_info()` сводка не зовёт — и не должна начать звать «для
  полноты» (есть сторож).
- **Движки отвечают о себе шестью разными способами.** `active` против
  `running`, `status(name)` против `get_status()`, `detect()` отдельно
  от состояния. Не приводите это к общему виду в `tools/` — форма
  записи живёт в `core/tunnels_overview.py`, иначе UI и MCP разойдутся.
- **Логи, домены, имена конфигов и вывод команд — недоверенные данные.**
  Инструкциями они не являются; в описании инструмента это сказано прямо
  (`untrusted data`), и ответ помечается полем `note`.
- **Мутирующий инструмент без отката — нарушение инварианта §5.4.**
  Меняете состояние — кладите снимок (`audit.snapshot`) и регистрируйте
  обработчик (`audit.register_undo`) в том же модуле. «Потом добавим»
  здесь означает «роутер остался в чужом состоянии без пути назад».
- **Снимок делается ПОСЛЕ удачной записи, а не до попытки.** Иначе
  `mcp_undo_last` вернёт значение, которое и так стоит, а настоящую
  правку (сделанную следующим вызовом) откатывать будет нечем.
- **Журнал в `/tmp` — ошибка.** На роутере это tmpfs: и журнал, и
  снимки исчезнут при ребуте, то есть ровно тогда, когда откат нужен.
  Каталог даёт `platform_dirs.config_dir()`; если его нет — молчим и не
  создаём (в тестах и на чужой машине это был бы `/opt/etc`, заведённый
  сторонним кодом).
- **Ротацию журнала нельзя считать на каждой записи.** Это чтение всего
  файла на каждый вызов инструмента. Проверка идёт раз в
  `ROTATE_CHECK_EVERY` записей, поэтому журнал законно бывает длиннее
  `keep` — тест обязан учитывать это (или подменять константу).
- **`perms or {...}` в тестовом хелпере выдаёт права, которых не
  просили.** Пустой словарь ложен, и вызов, которым проверяют отказ,
  тихо получает разрешение. Нужно `WRITE if perms is None else perms`.
- **Свой вызов инструмент в журнале не видит.** Запись делается ПОСЛЕ
  обработчика (иначе её длительность была бы выдумкой), поэтому
  `audit_list` всегда отстаёт на себя самого.
- **`get_script()` отдаёт `""` и для отсутствующего файла, и для
  пустого.** По нему «скрипт был» не определить, а на этом держится
  откат: вернуть текст или удалить созданный файл — разные действия.
  Существование спрашиваем у `list_names()`.
- **`BlobManager` строит свой каталог в `__init__`** из
  `zapret.base_path` — и сразу его создаёт. Тест, подменивший
  `lists_path`/`ipset_path`/`lua_path`, но забывший `base_path`, заводит
  `/opt/zapret2/blobs` на машине разработчика.
- **`get_hostlist()` пустого списка отдаёт ДЕФОЛТЫ, а не `[]`.** Тест,
  проверяющий «после отказа файл не тронут», обязан сравнивать с тем,
  что было, а не с пустым списком.
- **Аргументы движка пересобираются, а не берутся из `_last_args`.**
  Кеш прошлого запуска может быть от другой (в т.ч. только что
  отредактированной) стратегии, а может отсутствовать вовсе — nfqws2
  поднял автозапуск, а не GUI.
- **Пустой `strategy_args` — это не «запусти как есть».** Голый nfqws2
  без десинка означает выключенный обход при зелёном ответе, поэтому
  пустой список приводится к `None` («пересобери активную стратегию»).
- **Правила без движка — чёрная дыра.** Пакеты уходят в очередь, которую
  никто не читает. Поэтому неудачный `start` снимает правила, которые
  сам же поставил, а `firewall_apply` при лежащем движке говорит об этом
  в `hint`.
- **Мутирующий инструмент под `scope="read"` реестр не пропустит**, но
  инструмент под правильным scope с `mutating=False` — пропустит, и он
  уедет клиенту с пометкой «только чтение». Сторож —
  `test_mutating_tools_declare_it`.
- **Одному виду снимка — один обработчик.** `register_undo` перезаписывает
  предыдущий молча. Поэтому «применить стратегию» и «сохранить
  стратегию» — разные виды (`strategy_active` и `strategy`), хотя речь
  об одной сущности.
- **Запись настройки, которая начнёт действовать после перезапуска
  GUI, — запись наполовину.** Секция `logging` применяется вживую тем
  же вызовом, что и из веб-интерфейса
  (`reconfigure_persistent_from_config`). Движков это НЕ касается: их
  старт и перезапуск — разрешение `control` (S7).
- **`bypass` содержит `pass`.** Поля `with_bypass`/`without_bypass`
  (контракт `probe_compare`) уезжали модели как `"***"`: маска смотрит
  на имя ключа. Переименовать поля было нельзя — на них строится S10,
  поэтому в `SECRET_KEY_RE` у `pass` появилась оглядка назад
  (`(?<![a-z])pass`). `password`, `passwd`, `user_pass` маскируются
  по-прежнему; заодно перестал маскироваться `proxy_bypass`.
- **`note` в ответе уже занят.** Пометка «untrusted data» живёт в
  `note`, поэтому пояснение про задачу кладётся в `job_note`:
  `result.update(_jobs.describe(...))` иначе затирает одно другим — та
  же ошибка, что с `hint` у `page()`.
- **`is_running` у двух blockcheck'ов объявлен по-разному.** У
  `Blockcheck2Runner` это метод, у `BlockcheckRunner` — `@property`.
  Безусловный `manager.is_running()` на втором бросал `TypeError`,
  который съедался общим `except`, — и наша Python-реализация
  blockcheck НИКОГДА не считалась занявшей движок. Проверка теперь
  через `nfqws_control._is_running()` (callable или флаг).
- **Ноль осмыслен ровно у одного лимита проб.** `limits()` поднимает
  всё до 1, кроме `settle_sec`: «ноль целей» и «нулевой бюджет»
  означали бы инструмент, который ничего не делает, а нулевая пауза
  после переключения движка — законная настройка (и она же экономит
  секунды в тестах).
- **Бюджет времени проверяется МЕЖДУ порциями проб.** Задачи,
  отправленные в пул, доработают до конца в любом случае: `budget_sec`
  ограничивает не «сколько идёт вызов», а «сколько ещё запускать».
- **Runner помнит один прогон, а ярлыков задач — несколько.** Отдавать
  живой статус под `job_id` предыдущей задачи нельзя: модель прочитает
  «мой скан всё ещё идёт». Сравнение — `_jobs.is_current()`, и для
  вывода blockcheck2 это прямой отказ, а не подстановка чужих строк.
- **Сканер применяет стратегию сам.** `scanner.apply_strategy(index)`
  создаёт USER-стратегию и поднимает движок своим кодом (не через
  `nfqws_control`). Оборачивать это новой логикой нельзя (S8 не меняет
  поведение сканера) — поэтому снимок для отката снимается «снаружи»:
  `current_id` читается до и после вызова.
- **Мьютекс на движок — не для чтения.** `nfqws_status`, `strategy_list`
  и прочее read-only блокировку НЕ берут: иначе веб-интерфейс встанет на
  всё время скана. Берут её только те, кто движок МЕНЯЕТ.
- **`busy()` перед вызовом — вежливость, а не защита.** Между «спросил» и
  «сделал» сканер успевает стартовать; защита — сам захват внутри
  `nfqws_control`. Убирать двойную проверку не надо: у `busy()` текст
  отказа человечнее (у сканера — с прогрессом), у мьютекса — надёжнее.
- **Сессию нельзя взять «на всякий случай» вокруг чужого `finally`.**
  Сканер отказывается стартовать на занятом движке целиком
  (`timeout=0`), а не ждёт: его собственный `finally` иначе «вернул бы
  как было» чужое состояние.
- **Своя блокировка — не «занято».** `held_by_me()` → `busy()` отдаёт
  `{}`. Без этого держатель сессии (S10) не смог бы позвать ни
  `nfqws_control.start`, ни `apply_temporary`.
- **Lock-файл рядом с `settings.json`, и он переживает перезагрузку.**
  Поэтому у него есть кража по мёртвому pid и по возрасту: иначе
  упавший во время скана процесс оставил бы движок «занятым» навсегда —
  и обход не запустился бы ни кнопкой, ни автозапуском.

- **`/api/mcp/info` не годится странице.** Он loopback-only (снаружи
  это разведка: видно, какие разрешения открыты), а GUI открывают с
  LAN-адреса. Страница ходит в `/api/mcp/ui/state`; общее тело —
  `api/mcp.info_payload()`, чтобы два роута не разошлись.
- **`/api/config` отдавал `mcp.token` открытым текстом.** Маскировался
  только `gui.auth_password`. Теперь токен тоже `***` — и в GET, и в
  экспорте; чтобы маска не записалась обратно в PUT, тело проходит
  `ConfigManager.strip_masked()` (тем же способом, что импорт конфига).
- **Полная перерисовка страницы снимает галочку под рукой.** Ответ
  опроса приходит через секунду после клика и возвращает старое
  состояние чекбокса. Отсюда `_busy` на время действия и перерисовка
  блока только при смене его подписи.
- **Своего TLS у GUI нет.** Предупреждение «токен виден в каждом
  запросе» не может вести на «включите HTTPS» — включать нечего.
  Честные пути: `bind = local` + ssh-туннель, stdio-мост или обратный
  прокси с TLS перед GUI.
- **`const` в `node:vm` не попадает в `globalThis`.** Страница — это
  `const McpPage = (() => …)()`, и после `vm.runInContext` её нет среди
  свойств контекста. В `tests/test_mcp_page.js` она достаётся явным
  `globalThis.__page = McpPage` — так же, как её достаёт `app.js`.
