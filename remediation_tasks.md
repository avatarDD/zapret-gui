# План исправления замечаний (Remediation Tasks Checklist)

Данный файл содержит сгруппированный по модулям список задач для автоматического внесения исправлений в кодовую базу `zapret-gui` на основе мета-ревью.

## 1. Внедрение эталонных реализаций и замена Teleproxy

Данные задачи должны быть выполнены в первую очередь, так как они полностью заменяют старую логику туннелей и телеграм-прокси готовыми протестированными решениями:

- [x] **INTEGRATION-001** 🔴 [CRITICAL] Перенос эталонных файлов в проект
  - **Действие:** Скопировать следующие файлы из папки `D:\netcreaze\review\etalon` в соответствующие папки `D:\netcreaze\zapret-gui`:
    - `warp_in_warp.py` → [core/warp_in_warp.py](file:///D:/netcreaze/zapret-gui/core/warp_in_warp.py)
    - `warp_in_warp_watchdog.py` → [core/warp_in_warp_watchdog.py](file:///D:/netcreaze/zapret-gui/core/warp_in_warp_watchdog.py)
    - `tgproxy_manager.py` → [core/tgproxy_manager.py](file:///D:/netcreaze/zapret-gui/core/tgproxy_manager.py)
    - `tgproxy_api.py` → [api/tgproxy.py](file:///D:/netcreaze/zapret-gui/api/tgproxy.py) *(обратите внимание на смену имени файла!)*
    - `tgproxy.js` → [web/js/pages/tgproxy.js](file:///D:/netcreaze/zapret-gui/web/js/pages/tgproxy.js)
  - **Также скопировать в build-папку:**
    - `warp_in_warp.py` → `build/data/usr/share/zapret-gui/core/warp_in_warp.py` 
    - `warp_in_warp_watchdog.py` → `build/data/usr/share/zapret-gui/core/warp_in_warp_watchdog.py` 
    - `tgproxy_manager.py` → `build/data/usr/share/zapret-gui/core/tgproxy_manager.py` 
    - `tgproxy_api.py` → `build/data/usr/share/zapret-gui/api/tgproxy.py` 
    - `tgproxy.js` → `build/data/usr/share/zapret-gui/web/js/pages/tgproxy.js` 

- [x] **INTEGRATION-002** 🔴 [CRITICAL] Удаление устаревших файлов Teleproxy и Watchdog
  - **Действие:** Полностью удалить или отключить следующие неиспользуемые файлы в проекте:
    - [core/teleproxy_manager.py](file:///D:/netcreaze/zapret-gui/core/teleproxy_manager.py) (заменен на `tgproxy_manager.py`) 
    - [core/tgproxy_watchdog.py](file:///D:/netcreaze/zapret-gui/core/tgproxy_watchdog.py) (функции watchdog встроены в системный init-скрипт `S99tg-ws-proxy` и `S97tg-mtproxy` и не требуют питоновского watchdog-потока)
    - Удалить их аналогичные копии из папки `build/data/usr/share/zapret-gui/core/`

- [x] **INTEGRATION-003** 🔴 [CRITICAL] Развертывание tg-ws-proxy-go
  - **Действие:** Обеспечить сборку и установку пакета `tg-ws-proxy` на целевое устройство (архитектура arm64/mipsel/mips) из исходников [tg-ws-proxy-go](file:///D:/netcreaze/tg-ws-proxy-go). Убедиться, что init-скрипт `S99tg-ws-proxy` и конфигурационные файлы размещены в `/opt/etc/init.d/` и `/opt/etc/tg-ws-proxy/` соответственно.

- [x] **INTEGRATION-004** 🔴 [CRITICAL] Очистка следов Teleproxy в конфигурациях и установщиках
  - **Действие:** Полностью зачистить упоминания устаревшего `teleproxy` в системных модулях:
    - В [core/config_manager.py](file:///D:/netcreaze/zapret-gui/core/config_manager.py) удалить секцию с дефолтами `teleproxy_secret`, `teleproxy_domain` и `teleproxy_direct_dc`. Убедиться, что параметр `engine` не предлагает опцию `teleproxy` (оставить только `tgwsproxy` и `mtproto` как валидные движки).
    - В [core/ext_binary_installer.py](file:///D:/netcreaze/zapret-gui/core/ext_binary_installer.py) удалить запись 'teleproxy' из словаря `BINARIES`.
    - В [core/update_checker.py](file:///D:/netcreaze/zapret-gui/core/update_checker.py) удалить функцию `_check_teleproxy()` и её вызовы.
    - В [tests/test_ext_binary_installer.py](file:///D:/netcreaze/zapret-gui/tests/test_ext_binary_installer.py) удалить тест `test_teleproxy_arm64_only()`.

## 2. Остальные задачи исправления замечаний по модулям (137 задач)

### Модуль / Файл: `General/Integration`
Количество задач: 15

- [x] **MR-117** 🟡 [LOW] Dashboard — emoji icons вместо SVG
  - **Описание:** Dashboard использует emoji icons (`⚡ 🎭 ✈ 🔍 💚`) для VPN/monitoring cards, в то время как rest of UI использует inline SVG (sidebar.js:11-31, toast.js:13-16, dashboard.js:34-49 для top-row cards).
  - **Действие:** Заменить на SVG, consistent с sidebar icons.

- [x] **MR-18** 🔴 [HIGH] `block_detector._monitored` растёт без ограничений
  - **Описание:** Каждый новый домен из dnsmasq/AdGuard-логов добавляется в `self._monitored` и **никогда не эвиктируется**. Нет LRU, нет TTL, нет size cap. На семейном роутере с ~10 000 уникальных доменов в неделю, dict достигает сотен MB за месяцы. `get_results()` возвращает только top 200, так что bloat невидим пользователю.
  - **Действие:** ```python
MAX_MONITORED = 2000
if len(self._monitored) > MAX_MONITORED:
    for k in sorted(self._monitored,
                    key=lambda d: self._monitored[d]["first_seen"])[:500]:
        del self._monitored[k]
```

- [x] **MR-22** 🟠 [MEDIUM] `awg_manager._do_up` блокирует manager-lock на 15 секунд
  - **Описание:** `AwgManager.up` берёт `self._lock` на весь `_do_up`. Внутри `_run([bin_go, ifname], timeout=15, env=...)` — синхронный `subprocess.run` с 15-секундным таймаутом. amneziawg-go документирован (docstring строки 5-6) как fork'ающий себя, но если конкретный билд не fork'ает (или forking медленный на cold cache), менеджер блокирует до 15s. Всё это время **все** остальные AWG-операции (`list_interfaces`, `status`, `down` другого iface, watchdog `_tick`) блокируются на lock.
  - **Действие:** Использовать `subprocess.Popen` с `start_new_session=True` и poll для появления UAPI-сокета (`/var/run/wireguard/<iface>.sock`) вместо блокирующего `subprocess.run`. Или сократить timeout до 3s и считать большее как «демон не fork'нул — kill and retry».

- [x] **MR-28** 🔴 [HIGH] `_restart_log` мутируется во время итерации (`get_status`)
  - **Описание:** `_tick()` делает `self._restart_log.setdefault(iface, [])` и `history[:] = [...]` **без `self._lock`**. `get_status()` итерирует `self._restart_log.items()` под lock. Concurrent API call + tick → `RuntimeError: dictionary changed size during iteration`.
  - **Действие:** Брать `self._lock` вокруг всех мутаций state в `_maybe_restart` и `_resurrect_down_autostart`.

- [x] **MR-34** 🔴 [HIGH] NDMS backend тихо дропает IPv6 правила
  - **Описание:** ```python
if not net or ":" in net:
    # IPv6 пока не поддерживаем для NDMS-static-route
    continue
```
На Keenetic с NDMS доступным, менеджер роутит domain/CIDR правила через `ndms_backend`, когда `target_iface` — нативный NDMS-интерфейс. Любой IPv6 CIDR или AAAA-resolved IP тихо дропается — правило декларирует успех (`ok=True` для v6-части через `cidr_errors`, который не propagated как `ok=False`).
  - **Действие:** Либо реализовать `ipv6 route`/`ipv6 policy` NDMS-команды, либо fall back на ip-rule-backend для v6-части с логированием.

- [x] **MR-36** 🔴 [HIGH] Все CIDR `ip rule` шарят `BASE_PRIORITY = 10000`
  - **Описание:** Каждое CIDR-правило получает priority 10000. Linux позволяет несколько правил с одинаковым priority, но оценивает в порядке вставки — для overlapping CIDR (например `0.0.0.0/0` + `1.2.3.4/32`) результат недетерминирован между reapply. Хуже: `_remove_cidr` делает `ip rule del to <cidr> lookup <table>` (без priority) — если два правила с тем же CIDR для разных таблиц, удаляется только одно (другое утекает).
  - **Действие:** Derive priority из `rule.priority` field (уже есть в `RoutingRule`, но не используется) или `10000 + index`. Всегда включать `priority` в `ip rule del`.

- [x] **MR-40** 🟠 [MEDIUM] IPv6 anti-leak DROP rule глобальна — ломает legitimate IPv6 даже к LAN
  - **Описание:** ```python
return [["ip6tables", "-A", "FORWARD", "-j", "DROP"]]
```
Когда `ipv6_policy="drop"` и scope=forward, одно blanket DROP-правило вставляется в IPv6 FORWARD. Дропает **весь** forwarded IPv6 — включая трафик между LAN-сегментами, к локальному IPv6-роутеру, к другому туннелю. Нет bypass для `::1`, link-local, ULA prefixes.
  - **Действие:** Использовать named-chain pattern (как self-scope вариант уже делает), RETURN для bypass prefixes, затем DROP. Вставлять в top of FORWARD.

- [x] **MR-42** 🔴 [HIGH] `ext_binary_installer` — нет обработки GitHub rate-limit (403/429)
  - **Описание:** `github_latest_release` делает один `urlopen` на `api.github.com/repos/.../releases/latest`. Unauthenticated API limit = 60 запросов/час per IP. На 403/429 функция ловит exception и возвращает `{}` — caller возвращает `"Не удалось получить release с GitHub"` без retry, без backoff, без `Retry-After` header handling. `download_file` (строка 92) вызывает `urlopen_via(...)` напрямую, **НЕ** `binary_installer.download_file` — без retry, без mirror fallback.
  - **Действие:** Использовать `binary_installer.download_file` (есть retry + exponential backoff + mirror support). Для API-call парсить `X-RateLimit-Remaining` и `Retry-After`, кешировать release JSON на disk с TTL, на 403/429 — sleep + retry. Поддерживать `Authorization: token <github_token>` если пользователь предоставил.

- [x] **MR-44** 🟡 [LOW] `ext_binary_installer` — partial downloads не resumable / не cleaned
  - **Описание:** Функция открывает `dest` для write и стримит чанки. Если соединение рвётся mid-download, `dest` остаётся partial. При следующем вызове `download_file` открывает `dest` с `"wb"` (truncate) — re-download с нуля. Нет HTTP `Range:` header, нет `.part` suffix + rename-on-complete. `finally:` (строки 313-320) чистит только tmp-файл, не partial dest.
Дополнительно: `install_binary_by_name` не сравнивает версию установленного бинарника с latest release tag — клик «Install» всегда re-download'ит ~10-30MB даже если пользователь уже на последней версии.
  - **Действие:** Использовать `binary_installer.download_file`. Для resume — писать в `dest + ".part"`, слать `Range: bytes=<size>-`, `os.rename(.part, dest)` только при завершении. Сравнивать `_get_version(cfg["dest"])` с `release["tag_name"]` перед скачиванием — если равны, `{"ok": True, "noop": True}`.

- [x] **MR-72** 🟠 [MEDIUM] `_check_tgproto` хардкод `has_update: False` — UI никогда не покажет update
  - **Описание:** Детальное описание отсутствует.
  - **Действие:** Внедрить исправления согласно архитектурным стандартам проекта.

- [x] **MR-75** 🔴 [HIGH] `tunnel_monitor` форкает `ss -tn` каждые 5 секунд
  - **Описание:** `_read_opera_stats()` и `_read_tgproxy_stats()` каждый вызывают `subprocess.run(["ss", "-tn", ...])` каждые 5s (`DEFAULT_COLLECT_INTERVAL`). Это **24 fork'а в минуту**, 14 000 в день. `ss` парсит `/proc/net/tcp` + netlink — non-trivial CPU на MIPS. Plus на Entware fork() churn фрагментирует RAM и жжёт CPU.
Дополнительно: «speed» (`conns * 1024`, `conns * 512`) — **фабрикуемая константа**, не реальный трафик. Misleading dashboard.
  - **Действие:** Читать `/proc/net/tcp` напрямую в Python (no fork), или поднять opera/tgproxy poll interval до 30s и кешировать socket-alive check.

- [x] **MR-76** 🔴 [HIGH] `tunnel_monitor._history` накапливает stale interface deques
  - **Описание:** Каждый новый `iface` получает `deque(maxlen=144)` entry. Когда interface исчезает (например WARP session re-established с `opkgtun1` → `opkgtun2`), старый deque остаётся навсегда. Каждый deque держит до 144 tuples ≈ 3 KB. За месяцы WARP-reconnect'ов, AWG config churn, и т.д. — slow leak, и хуже — UI показывает stale phantom interfaces в chart'е.
  - **Действие:** На каждом tick'е дропать entries для interfaces, не замеченных в последнем `_discover_interfaces()` call'е (с grace period 60s чтобы избежать flapping).

- [x] **MR-89** 🔴 [HIGH] Dashboard делает 7 HTTP-запросов каждые 3 секунды
  - **Описание:** Dashboard polls **6 endpoints параллельно каждые 3s** (`/api/status`, `/api/usque/configs`, `/api/opera-proxy/status`, `/api/tgproxy/status`, `/api/block-detector/status`, `/api/healthcheck/status`) плюс `/api/logs?n=15` — итого 7 HTTP-запросов каждые 3s, 140 запросов/минуту, бесконечно, даже когда tab hidden.
  - **Действие:** (a) Pause polling на `document.hidden`. (b) Один aggregate endpoint `/api/dashboard/summary`. (c) Поднять interval до 5-10s. (d) Кешировать `lastData` и update DOM только на diff.

- [x] **MR-95** 🟡 [LOW] `awg_watchdog._tick` блокирует watchdog-thread на длительность `mgr.restart()`
  - **Описание:** `_run_loop` вызывает `_tick()` синхронно. `_tick` итерирует все ifaces и может вызвать `mgr.restart(iface)` (строка 497), который берёт `AwgManager._lock` и держит через `_do_down` (1s ip cleanup) + 0.3s sleep + `_do_up` (15s amneziawg-go spawn + setconf + addresses + routes). На медленном MIPS-роутере один restart может занять 20+s. Всё это время OTHER ifaces' handshake-age checks skip'аются — второй туннель может умереть и не быть перезапущенным 20s.
  - **Действие:** Move `mgr.restart()` call в worker thread (или queue), letting `_tick` return immediately после enqueue. Track in-flight restarts per iface чтобы избежать double-enqueue.

- [x] **MR-96** 🔴 [HIGH] `update_checker` no last-known cache; GitHub failure вытирает версию
  - **Описание:** ```python
def _github_latest(repo: str) -> str:
    try:
        ...
    except Exception:
        return ""      # <-- no cache, no last-known
```
`get_cached_results()` возвращает `_results` (last successful), но `check_all()` перезаписывает `_results` новыми данными, где `latest=""` после failure. Так что как только GitHub unreachable, «latest known» version вытирается из cache.
  - **Действие:** Держать отдельный `_last_known_latest` dict, который обновляется только на success. При failure preserve предыдущий `latest` в result и добавить `"stale": True` flag.

### Модуль / Файл: `PR_BODY.md`
Количество задач: 1

- [x] **MR-148** 🟡 [LOW] Присутствие файлов метаданных PR в дереве репозитория
  - **Описание:** Вспомогательные файлы PR добавлены непосредственно в дерево исходных кодов.
  - **Действие:** Удалить файлы `PR_BODY.md` and `CHANGES.md` из дерева проекта.

### Модуль / Файл: `api/__init__.py`
Количество задач: 1

- [x] **MR-56** 🟠 [MEDIUM] Нет `/api/v1/` versioning
  - **Описание:** Весь API unversioned. PR claim «ни один существующий эндпоинт не изменён» подтверждается — но **новые** эндпоинты ship'ятся без versioning, так что «no breaking changes» guarantee не имеет escape-hatch для будущих модификаций **новых** роутов.
  - **Действие:** Ввести `/api/v1/` prefix для новых эндпоинтов, или хотя бы зарезервировать под future use.

### Модуль / Файл: `api/auto_remediation.py`
Количество задач: 1

- [x] **MR-59** 🟠 [MEDIUM] `/api/remediation/apply` — нет dry-run
  - **Описание:** `auto_apply=True` фиксирован; `run()` затем спавнит multi-minute strategy scan и/или firewall rewrite. Нет preview, нет in-flight lock на уровне API (см. ISSUE-010).
  - **Действие:** Добавить `dry_run=true` query param; в dry-run возвращать planned actions без применения.

### Модуль / Файл: `api/config_api.py`
Количество задач: 1

- [x] **MR-60** 🔴 [HIGH] `/api/config/export` утекает `auth_password` plaintext
  - **Описание:** `GET /api/config` маскирует `auth_password` до `"***"` (строки 28-29), но `POST /api/config/export` возвращает `cfg.export_json()` raw — полный plaintext включая `gui.auth_password`, AWG private keys, tunnel secrets.
  - **Действие:** Применять ту же маскировку в `api_config_export`. Либо вообще не экспортировать `gui.auth_password` и `*.private_key` без явного `?include_secrets=true`.

### Модуль / Файл: `api/scan.py`
Количество задач: 1

- [x] **MR-62** 🔴 [HIGH] `/api/block-detector/probe` принимает невалидированный domain → SSRF
  - **Описание:** `probe_now(domain)` resolve'ит через `getaddrinfo`, открывает TCP:443, делает TLS handshake, шлёт `HEAD / HTTP/1.1`. Нет валидации domain → атакующий использует роутер как internal-port scanner / TLS-fingerprint oracle.
  - **Действие:** Hostname regex (уже используется в `api/scan.py:53`); reject RFC-1918 resolved IPs; per-IP rate-limit.

### Модуль / Файл: `api/tunnel_optimizer.py`
Количество задач: 1

- [x] **MR-09** 🔴 [CRITICAL] `tunnel_optimizer` принимает `iface` без валидации → перезапись `/proc/sys`
  - **Описание:** ```python
path = "/proc/sys/net/ipv4/conf/%s/tcp_%s" % (iface, param)
with open(path, "w") as f: f.write(str(value))
```
`iface` приходит напрямую из тела `POST /api/optimizer/optimize` (`data.get("iface","")`), проверяется только на непустоту. `iface="../../tcp_rmem_max"` резолвится до глобального `tcp_rmem_max` и перезаписывает его значением 65536 → мгновенный TCP-throughput DoS на каждом сокете роутера.
  - **Действие:** ```python
import re
if not re.match(r"^[a-zA-Z0-9_-]{1,15}$", iface):
    return {"ok": False, "error": "invalid iface name"}
if not os.path.isdir("/sys/class/net/%s" % iface):
    return {"ok": False, "error": "iface does not exist"}
```

### Модуль / Файл: `api/update_checker.py`
Количество задач: 1

- [x] **MR-58** 🔴 [HIGH] `/api/updates/check` блокирует worker ~135s, нет dedup
  - **Описание:** `check_all()` запускает 9 sequential helpers; `_github_latest` shell'ит `curl --max-time 10` (`timeout=15`) для 5 из них. Worst case 9 × 15s ≈ 135s per click. Нет in-flight guard → параллельные вызовы спавнят 18 `curl`-процессов и исчерпывают GitHub 60-req/h unauth rate-limit.
  - **Действие:** Трекать in-flight `threading.Event`; возвращать `202 Accepted` + status URL; делегировать уже существующему `UpdateCheckerDaemon`.

### Модуль / Файл: `api/usque.py`
Количество задач: 1

- [x] **MR-08** 🔴 [CRITICAL] Path traversal в `/api/usque/register` → root RCE
  - **Описание:** ```python
config_name = data.get("name", "warp-default")          # нет валидации
config_path = os.path.join(config_dir, "%s.conf" % config_name)
return mgr.register(config_path)                        # usque пишет creds туда
```
`config_name` принимает `../../etc/init.d/S99evil` → `mgr.register()` делает `os.makedirs(dirname(config_path), exist_ok=True)` и запускает usque-бинарник с `--config <path>`, который пишет реальный WARP `.conf` по этому пути. На Entware `S99*` автозапускается при буте → **root RCE**.
  - **Действие:** ```python
import re
if not re.match(r"^[A-Za-z0-9_-]{1,64}$", config_name):
    return {"ok": False, "error": "invalid name"}
real_config_dir = os.path.realpath(config_dir)
real_config_path = os.path.realpath(config_path)
if not real_config_path.startswith(real_config_dir + os.sep):
    return {"ok": False, "error": "path traversal denied"}
```

### Модуль / Файл: `app.py`
Количество задач: 5

- [x] **MR-127** 🟠 [MEDIUM] Синхронная загрузка системных статусов при старте GUI приложения
  - **Описание:** Инициализация менеджеров Bottle блокирует старт GUI и API-запросы.
  - **Действие:** Инициализировать менеджеры лениво или запускать сбор статусов в фоновых потоках.

- [x] **MR-129** 🟠 [MEDIUM] Отсутствие корректного завершения (Graceful Shutdown) фоновых потоков
  - **Описание:** Фоновые потоки Watchdog и BlockDetector не останавливаются корректно при завершении сервера.
  - **Действие:** Зарегистрировать обработчики сигналов (SIGTERM/SIGINT) и вызывать методы `.stop()` для всех активных менеджеров.

- [x] **MR-57** 🟠 [MEDIUM] `json.loads(request.body.read())` вместо `request.json` — bypasses MEMFILE_MAX
  - **Описание:** Все новые модули читают body через `json.loads(request.body.read())` вместо bottle'овского `request.json`. Последний уважает `BaseRequest.MEMFILE_MAX = 16 MiB` (строка `app.py:30`) и возвращает 400 на невалидный JSON. Custom parser bypass'ит и то, и другое.
  - **Действие:** Перейти на `request.json` везде. Для upload-эндпоинтов — отдельный `before_request` hook с hard cap `Content-Length`.

- [x] **MR-65** 🟡 [LOW] `error500` в HTML-ветке утекает `str(error)` unescaped
  - **Описание:** HTML-ветка `error500` отдаёт `str(error)` un-escaped → reflected XSS если 500-msg содержит user input.
  - **Действие:** `html.escape(str(error))`.

- [x] **MR-66** 🟡 [LOW] `405 Method Not Allowed` возвращает HTML вместо JSON
  - **Описание:** Только 404 и 500 обработаны кастомно. 405 (Method Not Allowed) возвращает HTML через bottle's `ERROR_PAGE_TEMPLATE`, ломая JS fetch-wrappers, ожидающие JSON.
  - **Действие:** Добавить `@error(405)` handler, возвращающий `{"ok": False, "error": "method not allowed"}`.

### Модуль / Файл: `core/auto_remediation.py`
Количество задач: 6

- [x] **MR-10** 🔴 [CRITICAL] `auto_remediation.run()` не реентерабелен — двойное применение
  - **Описание:** В `run()` нет защиты от конкурентного вызова. `self._lock` берётся только на строке 101 для swap `_results`. Если два вызывающих (API + scheduler, или два клика пользователя) одновременно вызовут `run()`, оба итерируют `targets`, оба вызовут `scanner.start()` (строка 151) и `save_route(route)` (строка 180) — создаются дубликаты маршрутов и пересекающиеся strategy scan'ы.
  - **Действие:** ```python
def run(self, ...):
    with self._lock:
        if self._running:
            return {"ok": False, "error": "already running"}
        self._running = True
    try:
        # ... вся логика ...
    finally:
        with self._lock:
            self._running = False
```

- [x] **MR-123** 🟡 [LOW] Избыточные инлайн-импорты внутри функций
  - **Описание:** По всему проекту используются инлайн-импорты внутри методов, что замедляет вызовы.
  - **Действие:** Перенести импорты на уровень модуля, разрешив циклические зависимости через ленивую инициализацию.

- [x] **MR-142** 🟡 [LOW] Игнорирование статуса запуска сканера в `auto_remediation`
  - **Описание:** Метод `_apply_zapret` запускает фоновое сканирование, но игнорирует возвращаемый булев статус.
  - **Действие:** Проверять результат `scanner.start(...)` и возвращать соответствующий статус вверх.

- [x] **MR-32** 🟠 [MEDIUM] `auto_remediation._apply_dns_fix` — no-op, возвращает True
  - **Описание:** ```python
def _apply_dns_fix(self, domain: str) -> bool:
    try:
        from core.hosts_manager import get_hosts_manager
        hm = get_hosts_manager()
        log.info("auto-remediation: DNS fix для %s (требуется DoH/hosts)" % domain, ...)
        return True     # <-- нет реального фикса
```
`hm` получается, но не используется. `auto_apply=True` возвращает `applied=True` для DNS-classified блокировок, ничего не меняя на роутере.
  - **Действие:** Либо вызвать `hm.add_host(domain, correct_ip)` после пробы правильного IP через DoH (`dns_providers` рядом), либо возвращать `False` с ясным «manual action required» до завершения реализации.

- [x] **MR-33** 🟠 [MEDIUM] `auto_remediation._apply_tunnel` не проверяет здоровье туннеля
  - **Описание:** `_apply_tunnel` создаёт маршрут без проверки туннельного здоровья; декларирует успех по факту `save_route`. `apply_route` может вернуть успех (маршрут установлен), но туннель сам может не роутить трафик к `domain`. Нет follow-up пробы.
  - **Действие:** После `apply_route` повторно запустить `block_detector._probe(domain)` и возвращать `True` только если теперь успешно. Передавать probe-результат в `result["details"]`.

- [x] **MR-73** 🟡 [LOW] `auto_remediation.REMEDIATION_ACTIONS` не настраиваемый
  - **Описание:** Mapping DPI type → action — module-level constant. Пользователь не может, например, поменять `dns_fake` с `dns_fix` на `tunnel` без редактирования source. При этом `tunnel_priority` (WARP > AWG > opera > singbox) **настраиваем** через `_find_best_tunnel` (строки 194-206) — хорошо.
  - **Действие:** Перенести `REMEDIATION_ACTIONS` в config под `auto_remediation.actions` с текущим dict как default.

### Модуль / Файл: `core/awg_manager.py`
Количество задач: 3

- [x] **MR-16** 🔴 [HIGH] `awg_manager.save_config` — неатомарная запись несмотря на существующий `safe_io`
  - **Описание:** ```python
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    f.write(text)
try:
    os.chmod(path, 0o600)
```
Plain `open(path, "w")` **тратирует существующий файл перед записью**. При потере питания (роутер выдернули из розетки) или `ENOSPC` посреди записи .conf остаётся пустым или частичным — при следующем буте `awg up` падает с «Ошибки конфига». В кодовой базе уже есть `core/safe_io.atomic_write_text` (`tempfile.mkstemp` → `fsync` → `os.replace`) — но `awg_manager` его не использует. `singbox_manager.save_config:391-395` и `mihomo_manager.save_config:205-209` делают свой `tmp + os.replace` (атомарно, но без fsync), а `awg_manager` не делает ни того, ни другого.
  - **Действие:** ```python
from core.safe_io import atomic_write_text
atomic_write_text(path, text)
os.chmod(path, 0o600)
```

- [x] **MR-20** 🟠 [MEDIUM] `awg_manager._run_hook` — `shell=True` с user-supplied PostUp/PostDown (RCE)
  - **Описание:** ```python
r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
```
`cmd` приходит из `[Interface] PostUp = ...` строки импортированного .conf-файла. Opt-in gate `awg.allow_hooks=false` по умолчанию (строки 1534-1538), но как только пользователь включит (а docstring поощряет power-users), ЛЮБОЙ импортированный .conf из публичной подписки запускает arbitrary shell как root. Распространённые WireGuard-подписки публикуют конфиги с `PostUp = iptables ...` или `PostUp = curl ...`.
  - **Действие:** Либо (a) парсить cmd и exec без shell (`subprocess.run(shlex.split(cmd), ...)`), либо (b) sandbox через `firejail`/`chroot`, либо (c) как минимум — громкое warning-логирование при каждом hook-запуске (сейчас INFO level), и per-hook confirmation prompt в GUI.

- [x] **MR-94** 🟡 [LOW] `awg_manager._apply_setconf` — temp file в system `/tmp`, не same FS как config
  - **Описание:** `tempfile.NamedTemporaryFile("w", delete=False, prefix="awg-setconf-", suffix=".conf")` default'ит в `/tmp` (tmpfs на Entware, RAM-backed). На 128MB роутере большие setconf blobs (multiple peers с длинными AllowedIPs lists) едят RAM. Также `os.chmod(tmp_path, 0o600)` вызывается ДО write — но `tempfile.NamedTemporaryFile` уже создаёт с 0o600 на POSIX, так что explicit chmod redundant.
  - **Действие:** `tempfile.NamedTemporaryFile(dir=platform.run_dir, ...)` чтобы temp file лежал на той же FS, что rest of run state (обычно `/opt/var/run` на Entware).

### Модуль / Файл: `core/binary_installer.py`
Количество задач: 1

- [x] **MR-43** 🟡 [LOW] `binary_installer._download_once` тратирует dest до завершения стрима
  - **Описание:** `with open(dest_path, "wb") as f:` открывает (тратируя) ДО чтения `Content-Length`. Если сервер вернёт 4xx/5xx после headers, `dest_path` остаётся 0-byte файлом. Caller `download_file:198-203` ловит `URLError`, но не unlink'ает 0-byte dest. При следующей retry-попытке `_download_once` снова truncate'ит — но если retries исчерпаны, у пользователя 0-byte файл, который выглядит как «successful» download для `os.path.isfile`-проверок.
  - **Действие:** Писать в `dest_path + ".part"`; только `os.rename(.part, dest_path)` после успешного `with open(... "wb")`. Cleanup `.part` на exception.

### Модуль / Файл: `core/block_detector.py`
Количество задач: 11

- [x] **MR-141** 🟠 [MEDIUM] Состояние гонки (Race Condition) при итерации по `BlockDetector._monitored`
  - **Описание:** Метод `get_results` итерируется по monitored напрямую без копирования/блокировок во время фоновой записи.
  - **Действие:** Обернуть операции в блокировки `self._lock` или использовать копирование `list(self._monitored.items())`.

- [x] **MR-147** 🟡 [LOW] Мертвая ветка `SSLCertVerificationError` из-за использования `CERT_NONE`
  - **Описание:** Поскольку SSL контекст настраивается с `ssl.CERT_NONE`, SSLCertVerificationError никогда не возникнет.
  - **Действие:** Удалить ветку перехвата `ssl.SSLCertVerificationError` или включить проверку.

- [x] **MR-29** 🟠 [MEDIUM] `block_detector` socket leak на TLS handshake error
  - **Описание:** `_probe()` создаёт `sock = socket.create_connection(...)`. На TLS error-paths (`SSLCertVerificationError`, `SSLError`, `OSError`, generic `Exception`) функция return'ит без `sock.close()` или `tls.close()`. Только happy-path закрывает `tls` (который закрывает underlying socket). `sock` также не закрывается, если `ctx.wrap_socket` райзнет до присваивания `tls`.
  - **Действие:** try/finally с явным close.

- [x] **MR-30** 🟠 [MEDIUM] `block_detector` хардкод 60s wait игнорирует `interval_sec`
  - **Описание:** `_run_loop` читает `interval = cfg.get("block_detector", "interval_sec", default=300)` (строка 87), **но не использует** — wait захардкожен `self._stop_evt.wait(60)` (строка 92). Пользовательская настройка `interval_sec: 300` тихо игнорируется; детектор тикает каждые 60s.
  - **Действие:** `self._stop_evt.wait(interval)`.

- [x] **MR-46** 🟠 [MEDIUM] `block_detector._probe()` HTTP-тест возвращает "ok" для любого ответа
  - **Описание:** ```python
if b"200" in data or b"301" in data or b"302" in data:
    return "ok"
return "ok"  # есть ответ — считаем доступным
```
Второй `return "ok"` глотает каждый non-200 ответ — включая 403 (geo-block), 451 (legal block), 521 (Cloudflare down), и ISP redirect pages (часто 200 с HTML-stub). 4-stage probe должен detect ISP pages (см. `blockcheck._run_isp_phase` через `detect_isp_page`), но `block_detector._probe` это не использует — у него более простой, неправильный эвристик.
  - **Действие:** Заменить второй `return "ok"` на `return "http_cutoff"`. Лучше — переиспользовать `core.testers.isp_detector.detect_isp_page` для stage 4.

- [x] **MR-47** 🟠 [MEDIUM] `block_detector._from_af_packet` — stub, возвращает `[]`
  - **Описание:** ```python
def _from_af_packet(self) -> list:
    """AF_PACKET DNS-сниффинг (заглушка — требует root)."""
    return []
```
И `_get_dns_source` (строки 140-151) возвращает `"af_packet"` когда ни dnsmasq log, ни AdGuard не найдены — что имеет место на большинстве дефолтных Entware-сетапов (dnsmasq не логирует по умолчанию без `log-queries`).
  - **Действие:** Либо реализовать AF_PACKET sniffing (`socket.socket(AF_PACKET, SOCK_RAW, ...)` — нужен root, который у GUI есть), либо detect «af_packet» и громко warning'ать: «DNS source auto-detection failed; enable dnsmasq log-queries».

- [x] **MR-48** 🔴 [HIGH] `block_detector._from_dnsmasq_log` — парсит половинчатую строку
  - **Описание:** ```python
f.seek(max(0, size - 10240))
data = f.read().decode("utf-8", errors="replace")
for line in data.splitlines():
    m = re.search(r"reply\s+(\S+)\s+is\s+", line)
```
Чтение 10 KB из середины лога разрезает строку пополам; `re.search` видит фрагмент типа `ple.com is 192.0.2.5` и не матчит (нет ведущего `reply `). Хуже: последний вызов мог уже распарсить эту строку, получаем duplicated partial matches в обратную сторону.
  - **Действие:** `f.seek(max(0, size-10240)); f.readline()` — пропустить past cut, итерировать с этого места.

- [x] **MR-53** 🟡 [MEDIUM (CROSS-CUTTING)] NO SIGTERM handler нигде в watchdog-слое
  - **Описание:** Grep по `core/` для `signal.SIGTERM` находит использование только в `*_manager.py:stop()` (отправка SIGTERM детям). Ни один watchdog-файл не устанавливает `signal.signal(SIGTERM, ...)`. Entware init-скрипты шлют SIGTERM при shutdown. Поскольку watchdog-потоки `daemon=True`, они убиваются резко; их child-subprocess'ы (usque, mihomo, и т.д.) **используют** `start_new_session=True` (хорошо — переживают), но чистый shutdown-sequence не запускается: temp-файлы остаются, in-flight restart-sequences abort'ятся посередине (например между `mgr.stop()` и `mgr.start()` в ISSUE-026), PID-файлы могут быть stale.
  - **Действие:** В main app entrypoint установить SIGTERM handler:
```python
def _shutdown(signum, frame):
    for getter in (get_usque_watchdog, get_tgproxy_watchdog, ...):
        try: getter()._stop()
        except: pass
    # join all threads with 5s timeout
    sys.exit(0)
signal.signal(signal.SIGTERM, _shutdown)
```

- [x] **MR-80** 🟡 [LOW] `block_detector._probe()` создаёт `ssl.create_default_context()` на каждый probe
  - **Описание:** `_probe()` создаёт свежий SSLContext для каждого domain. Context creation loads CA certs (~50 KB) каждый раз. С 200 domains/hour — significant CPU.
  - **Действие:** Кешировать один context на BlockDetector instance.

- [x] **MR-97** 🔴 [HIGH] `block_detector._tick()` — синхронные пробы блокируют daemon-thread
  - **Описание:** ```python
def _tick(self):
    new_domains = self._collect_dns_queries()
    for d in new_domains:
        if d not in self._monitored and d not in self._whitelist:
            self._monitored[d] = {...}
    for domain, info in list(self._monitored.items()):
        if (now - info["last_checked"]) < 3600:
            continue
        result = self._probe(domain, timeout)    # synchronous: DNS + TCP + TLS + HTTP
```
1. `_probe()` (строка 212) blocks up to `timeout=5`s per domain × N domains. Если 50 domains нуждаются в probing каждый час → 250s blocking на daemon-thread. Всё это время `stop_evt.is_set()` не check'ится, так что `stop()` unresponsive minutes.
2. `_monitored` (dict) мутируется без lock — `_tick()` пишет из daemon-thread, `get_results()` / `get_status()` / `probe_now()` читают из API-thread. Concurrent dict iteration в `get_results()` пока daemon `del`'ет / добавляет entries → `RuntimeError: dictionary changed size during iteration`.
3. `_from_dnsmasq_log()` (строка 153) читает last 10 KB лога каждый tick и возвращает **те же 50 domains** каждый раз — no offset tracking. `_monitored` dict grows monotonically: через неделю — tens of thousands stale entries. No eviction policy.
  - **Действие:** Thread pool для `_probe()`; track per-source cursor (byte offset / mtime) чтобы видеть только NEW domains; LRU eviction (например drop entries older than 7 days или cap at 1000). Wrap `_monitored` access в `self._lock`.

- [x] **MR-98** 🔴 [HIGH] `block_detector.probe_now()` блокирует API request до 5s
  - **Описание:** ```python
def probe_now(self, domain: str) -> dict:
    result = self._probe(domain, timeout=5)
    return {"domain": domain, "block_code": result, ...}
```
  - **Действие:** Запускать `_probe()` в worker thread, return `{"started": True}`; expose result через future-ID lookup, или просто poll `get_results()` для just-added domain.

### Модуль / Файл: `core/blockcheck.py`
Количество задач: 1

- [x] **MR-86** 🔴 [HIGH] `blockcheck._aggregate_dpi` priority list: IP_BLOCK менее информативен чем TLS_DPI
  - **Описание:** ```python
priority = [
    DPIClassification.TLS_DPI.value,
    ...
    DPIClassification.IP_BLOCK.value,
    DPIClassification.FULL_BLOCK.value,
    ...
]
for p in priority:
    if p in classifications:
        return p
```
Если 14 из 15 tested domains возвращают `TLS_DPI`, но один возвращает `IP_BLOCK` (например cloudflare.com на ISP, null-routing'ящем его IP), aggregate = `TLS_DPI`. `auto_remediation` тогда map'ит на `zapret_scan` для **каждого** target включая IP-blocked — сканер запустит 30+ TLS-стратегий, все упадут, потом auto-remediation trigger'ит `_apply_tunnel` только как fallback после того, как scanner сдаётся. Wasted 5-10 min CPU + flash writes (resume-state) per occurrence.
  - **Действие:** Аггрегировать per-target, не глобально. Pass per-target `dpi_classification` (уже есть в `TargetResult`) в `auto_remediation` (который уже читает `target.dpi_classification` — хорошо!), но ensure что `auto_remediation._apply_zapret` skip'ает targets classified как `ip_block`/`full_block` даже если global aggregate говорит `tls_dpi`.

### Модуль / Файл: `core/config_manager.py`
Количество задач: 2

- [x] **MR-07** 🔴 [CRITICAL] GUI по умолчанию без аутентификации на `0.0.0.0`
  - **Описание:** ```python
DEFAULT_CONFIG["gui"] = {"host": "0.0.0.0", "auth_enabled": False, "auth_password": ""}
```
Из коробки GUI слушает на всех интерфейсах, включая WAN. Любой, кто достучится до порта, может вызывать `/api/awg/install`, `/api/usque/register`, `/api/_install_upload`-эндпоинты. Без токена, без сессии; CSRF-проверка в `app.py:474` срабатывает только если браузер шлёт `Origin` **и** `auth_enabled=true`.
  - **Действие:** Шипать с `auth_enabled=True` и одноразовым паролем, печатаемым при первом буте. Default-bind `127.0.0.1`/LAN; WAN — только через явный opt-in.

- [x] **MR-134** 🟡 [LOW] Несоответствие UDP диапазона портов Discord Voice официальной документации
  - **Описание:** В конфигурации nfqws2 указан диапазон портов UDP для Discord `49152:65535`.
  - **Действие:** Скорректировать диапазон портов в конфиге по умолчанию на `50000:65535` для соответствия спецификации Discord.

### Модуль / Файл: `core/dns_routing.py`
Количество задач: 3

- [x] **MR-139** 🔴 [CRITICAL] Неработоспособная реализация Per-domain DNS маршрутизации
  - **Описание:** DNS-маршрутизация генерирует файл, но он не подключается к dnsmasq и dnsmasq не перезапускается.
  - **Действие:** Использовать интеграционные методы для автоматического добавления `conf-file` и выполнения релоада dnsmasq.

- [x] **MR-61** 🔴 [HIGH] dnsmasq directive injection через `/api/dns-routing/rules`
  - **Описание:** `add_rule` валидирует `dns_server`, **но не** `domain`. Apply step пишет `server=/%s/%s\n % (domain, dns_ip)` в dnsmasq include file. `domain="x.com\naddn-hosts=/etc/passwd"` производит literal newline + attacker-controlled directive → root-level dnsmasq config injection.
  - **Действие:** Strict hostname regex; reject `/`, `\n`, `\r`, `#`, whitespace.

- [x] **MR-83** 🟠 [MEDIUM] `dns_routing.apply()` — блокирующий DNS-lookup для DoH URLs
  - **Описание:** ```python
if server.startswith("https://"):
    ...
    return socket.gethostbyname(host)   # blocks up to ~30s on DNS timeout
```
Для каждого DoH-style rule — синхронный DNS lookup. Если 5 rules используют DoH URLs и DNS медленный, `apply()` blocks API caller на 150s.
  - **Действие:** Pre-resolve один раз при config-load, кешировать IPs в `DNS_SERVERS` dict, использовать cached IPs в `apply()`.

### Модуль / Файл: `core/ext_binary_installer.py`
Количество задач: 3

- [x] **MR-06** 🔴 [CRITICAL] Скачанные бинарники не проверяются по sha256 (supply-chain attack)
  - **Описание:** Полный pipeline download→install использует `shutil.copy2(source, dest); os.chmod(dest, 0o755)` — без `sha256`, без GPG-подписи, без сравнения с манифестом. Соседний `binary_installer.py:255-276` предоставляет `sha256_of` + `verify_sha256` и `fetch_verify_extract_install`, который проверяет — но `ext_binary_installer` его игнорирует. В словаре `BINARIES` (строки 128-169) нет `sha256`-поля ни для одного из 4 бинарников.
  - **Действие:** Добавить поле `sha256` per release tag в `BINARIES`. Cheksum'ы брать из отдельного подписанного канала (или хардкодить known-good хэши per tag). Вызывать `binary_installer.verify_sha256(tmp_path, expected)` перед `install_binary`. Использовать `binary_installer.install_binary` (атомарный `os.replace` с backup) вместо `shutil.copy2`.

- [x] **MR-138** 🔴 [CRITICAL] Сломанная логика распаковки архивов из-за жесткого суффикса `.bin`
  - **Описание:** Временный файл создается с суффиксом `.bin`, из-за чего проверка распаковки архивов возвращает ложь.
  - **Действие:** Определять суффикс временного файла на основе расширения скачиваемого ассета (URL).

- [x] **MR-143** 🔴 [CRITICAL] Уязвимость Path Traversal при извлечении tar-архивов бинарников
  - **Описание:** Метод `tar.extract` вызывается без валидации имен членов архива.
  - **Действие:** Добавить валидацию путей членов архива (проверка, что итоговый путь лежит внутри целевого каталога).

### Модуль / Файл: `core/geosite_importer.py`
Количество задач: 1

- [x] **MR-81** 🟠 [MEDIUM] `geosite_importer._parse_protobuf_geosite` читает весь файл в память
  - **Описание:** ```python
def _parse_protobuf_geosite(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()      # full file в RAM
```
Типичный `geosite.dat` от v2fly — 8-15 MB. Плюс `result` dict аккумулирует каждый domain. На 64 MB роутере с ~30 MB free — работает, но при импорте нескольких categories последовательно peak RAM ~30-40 MB. Плюс Python's per-string overhead (~50 bytes/domain × 500 000 domains = 25 MB только strings) → OOM-kill bottle server.
  - **Действие:** Stream-parse protobuf (итерировать field-by-field без materializing всего `data`), или `mmap.mmap()`. Как минимум, `import_category(path, category, list_id)` с early-exit после нахождения target category.

### Модуль / Файл: `core/list_updater.py`
Количество задач: 1

- [x] **MR-63** 🔴 [HIGH] `add_from_url` позволяет arbitrary http(s) URL → SSRF
  - **Описание:** `POST /api/lists/curated {"url":"http://192.168.0.1/admin"}` → `_fetch` → `urlopen_via(...)`. Response body stored as domain list и echoed back через `GET /api/lists/<id>`. Нет host allow-list, нет RFC-1918 egress block.
  - **Действие:** Allow-list hostnames (github.com, raw.githubusercontent.com, itdoginfo, …); reject resolved IPs в private ranges.

### Модуль / Файл: `core/log_buffer.py`
Количество задач: 1

- [x] **MR-17** 🔴 [HIGH] `log_buffer.py` — неатомарная ротация + truncate-on-failure
  - **Описание:** `_write_to_file()` и `_rotate_file()` не защищены никаким lock'ом. Два потока, логирующие конкурентно, оба могут обнаружить `size > MAX_FILE_SIZE`, оба вызвать `_rotate_file()`, оба `open(path, "w")` (тратируя), затем `writelines(lines[half:])` — интерливинг или wiping лога. Хуже: `_rotate_file` открывает с `"w"` **до** того, как `readlines()` в caller'е успел прочитать — если `readlines()` райзнет, файл уже пуст. То же в `_write_persistent()` (строки 244-251) — persistent-лог лежит на flash (`cfg_dir/critical.log`), конкурентные записи могут повредить файл, от которого зависит post-reboot-диагностика.
  - **Действие:** ```python
with self._file_lock:
    if os.path.exists(path) and os.path.getsize(path) > MAX:
        tmp = path + ".tmp"
        with open(path) as f: lines = f.readlines()
        with open(tmp, "w") as f: f.writelines(lines[len(lines)//2:])
        os.replace(tmp, path)  # atomic на POSIX
    with open(path, "a") as f: f.write(entry.format_line() + "\n")
```

### Модуль / Файл: `core/ndms/commands.py`
Количество задач: 2

- [x] **MR-23** 🟠 [MEDIUM] NDMS multi-step операции не транзакционные
  - **Описание:** Каждый `client.post()` = одна RCI-команда = одна CLI-мутация. Нет transaction-wrapper'а. Если `delete_fqdn_group` успешен, но `upsert_fqdn_group` падает (network blip, RCI timeout) — group удалена, но dns-proxy route всё ещё ссылается. `apply_device_rule` хуже: может оставить orphaned `ip policy` (rollback на 447 срабатывает только если `assign_host_policy` падает, но не если `save_running_config` падает).
  - **Действие:** Оборачивать multi-step apply в sequenced try/finally, который для каждого успешного шага вызывает симметричный `delete_*`.

- [x] **MR-52** 🟠 [MEDIUM] `_is_not_found_error` матчит "unknown" и "404" — маскирует реальные ошибки
  - **Описание:** ```python
return any(token in low for token in (
    "not found", "no such", "doesn't exist", "does not exist",
    "unknown", "404"))
```
«unknown» встречается во многих NDMS error-сообщениях, не означающих «объект не найден» — например «unknown command», «unknown interface state». Трактовка их как idempotent-delete-success тихо глотает реальные ошибки.
  - **Действие:** Сузить до конкретных фраз («not found», «no such», «does not exist»). Убрать «unknown» и «404».

### Модуль / Файл: `core/ndms/rci_client.py`
Количество задач: 1

- [x] **MR-51** 🟠 [MEDIUM] RCI client не сериализует POST-запросы глобально
  - **Описание:** `_lock` существует (строка 37), но берётся только внутри `is_available()` (строка 129). `_request()` и `post()` **не** держат lock. Keenetic RCI принимает каждый POST как одну CLI-команду. Concurrent POST'ы из нескольких bottle-workers (или из apply + watchdog reapply) интерливятся на CLI-уровне — Keenetic сериализует их внутренне, но ordering ответов становится недетерминированным, и `save_running_config` mid-batch может persist'нуть half-applied state.
  - **Действие:** Брать `_lock` в `post()` на время HTTP-call'а (или отдельный `_post_lock`, чтобы не блокировать `is_available`-чтения).

### Модуль / Файл: `core/ndms_backend.py`
Количество задач: 1

- [x] **MR-128** 🔴 [HIGH] Зависимость от ndmc для Keenetic без fallback на других прошивках
  - **Описание:** Настройка маршрутов и файрвола завязана на утилиту `ndmc` (Keenetic).
  - **Действие:** Интегрировать поддержку статической маршрутизации в существующий абстрактный механизм выбора сетевого бэкенда `choose_backend()` в `core/routing/rules.py` (который уже переключает Entware ipset, OpenWrt nftables и Keenetic-native) для корректного fallback на других ОС.

### Модуль / Файл: `core/nfqws_manager.py`
Количество задач: 1

- [x] **MR-125** 🟡 [LOW] Multi-WAN автодетект при каждом запуске nfqws2
  - **Описание:** Метод _detect_wan_interfaces запускается при каждом формировании аргументов nfqws2.
  - **Действие:** Кэшировать список обнаруженных WAN-интерфейсов в памяти или обновлять его асинхронно.

### Модуль / Файл: `core/opera_proxy_watchdog.py`
Количество задач: 3

- [x] **MR-135** 🟡 [LOW] Opera Proxy Watchdog не синхронизирует fail_count при внешнем старте
  - **Описание:** Watchdog сбрасывает `_fail_count` только при автоматическом перезапуске, но не при ручном GUI старте.
  - **Действие:** Сбрасывать `_fail_count` в 0 внутри метода `start()` менеджера или при ручной инициализации.

- [x] **MR-27** 🟠 [MEDIUM] `time.sleep()` внутри restart блокирует shutdown
  - **Описание:** Каждый watchdog `_do_restart` использует `time.sleep(1)` (или 2). Во время этого sleep поток не может наблюдать `_stop_evt`. Если `reconfigure()` вызвана mid-restart, поток продолжает работать 1-2s и может даже **стартовать новый subprocess после** запроса shutdown от пользователя.
  - **Действие:** ```python
if self._stop_evt.wait(1):
    return  # shutdown requested
```

- [x] **MR-50** 🟡 [LOW] `tunnel_optimizer.optimize_all_tunnels` обращается к private `monitor._discover_interfaces`
  - **Описание:** `interfaces = monitor._discover_interfaces()` — вызов name-mangled (`_`-префикс) метода на синглтоне другого модуля. Если `TunnelMonitor` отрефакторит `_discover_interfaces` (например, добавив caching), это молча сломается. Также результат включает `"__opera_proxy__"` etc., который `optimize_iface` пытается передать в `ip link set __opera_proxy__ mtu 1420` — фейлится (не real interface). `if iface.startswith("__"): continue` (строка 215) ловит это, но только потому, что кто-то заметил баг.
То же в `opera_proxy_watchdog.py:97` (`mgr._is_running()`), `update_checker.py:260` (`tgproxy_manager._detect_mtproto`).
  - **Действие:** Добавить public `TunnelMonitor.get_active_tun_ifaces() -> list[str]`. На manager'ах — public `is_running()` wrappers.

### Модуль / Файл: `core/routing/dnsmasq_integration.py`
Количество задач: 1

- [x] **MR-24** 🟠 [MEDIUM] `dnsmasq_integration.write_managed_file` неатомарна
  - **Описание:** ```python
text = "\n".join(lines).rstrip() + "\n"
try:
    with open(managed, "w") as f:
        f.write(text)
```
Plain `open(managed, "w")` тратирует файл перед записью. При kill посередине (SIGKILL при uninstall, OOM, disk full) dnsmasq при следующем SIGHUP читает полу-написанный файл и падает парсинг → ломается DNS для всех routed-доменов.
  - **Действие:** Писать в `managed + ".tmp"`, `fsync`, затем `os.rename` в `managed`. Или `safe_io.atomic_write_text`.

### Модуль / Файл: `core/routing/ipset_backend.py`
Количество задач: 1

- [x] **MR-35** 🔴 [HIGH] ipset/nftset: нет `maxelem` → крупные списки тихо переполняются
  - **Описание:** ```python
# ipset
rc, _o, err = _run(["ipset", "create", name, "hash:ip",
                    "family", fam, "hashsize", "1024", "timeout", "0"])
# nftset
rc, _o, err = _run(["nft", "add", "set", "inet", TABLE_NAME, name,
                    "{ type %s; flags interval; auto-merge; }" % typ])
```
Нет `maxelem` → kernel default 65536. Для Cloudflare (200+ префиксов), Discord (тысячи IP), или `geoip:ru` (~22 000 префиксов) set заполняется тихо; последующие IP дропаются с `set is full` в dmesg, но демон не знает. Domain-rule mark rules никогда не сработают для новых IP → leak вокруг туннеля.
  - **Действие:** Добавить `maxelem 1048576` (или настраиваемо). Для nft: `"{ type %s; flags interval; auto-merge; size 1048576; }"`.

### Модуль / Файл: `core/routing/manager.py`
Количество задач: 3

- [x] **MR-38** 🔴 [HIGH] `table_id_for` хэш имеет только 900 бакетов → коллизии между туннелями
  - **Описание:** ```python
def table_id_for(ifname: str) -> int:
    h = 0
    for ch in ifname:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return 100 + (h % 900)
```
Два по-разному названных интерфейса могут хэшироваться в один table ID (например `awg0` и `wg_test1`). Когда это происходит, оба interface шарят один `ip route table N default dev <iface>` slot — второй `ip route add default dev <iface2> table N` либо фейлится (`File exists`), либо, если `replace` — перетирает первый. CIDR-правила, указывающие на table N, роутят на того, кто выиграл race.
  - **Действие:** Persist reserved-table registry в `settings.json` (например `routing.table_map: {awg0: 200, wg0: 201, ...}`) с collision-check при аллокации. Hash только если registry пуст.

- [x] **MR-39** 🟠 [MEDIUM] `_remove_ipt_family` возвращает True безусловно — прячет cleanup failures
  - **Описание:** ```python
def _remove_ipt_family(self, ipt_cmd) -> bool:
    for table, chain in self._IPT_CHAINS:
        self._remove_ipt_chain(ipt_cmd, table, chain)
    for table, hook, name in self._IPT_NAMED_CHAINS:
        self._remove_ipt_named_chain(ipt_cmd, table, hook, name)
    return True          # ← никогда не отражает per-call rc
```
Даже если каждый `_remove_ipt_chain` / `_remove_ipt_named_chain` падает (xtables lock contention, iptables binary пропал), функция рапортует успех. Caller логирует «Правила firewall сняты» при живых правилах. Та же проблема в `_remove_cidr` и `teardown_mark_rule`.
  - **Действие:** Трекать per-call rc и возвращать aggregate. `No such file or directory` трактовать как успех, реальные ошибки — как failure.

- [x] **MR-41** 🟠 [MEDIUM] `reapply_all` открывает delete-then-create окно без lock
  - **Описание:** `reapply_all` итерирует правила и вызывает `_remove(rule)` затем `_apply(rule)` per rule, держа только `self._lock` (который сериализует manager-вызовы, но не предотвращает in-flight iptables/ip-rule эффекты). Между `_remove` и `_apply` пакеты к CIDR/domain этого правила текут через main table → leak window от миллисекунд до секунд в зависимости от backend.
  - **Действие:** Для nft backend — строить новую table атомарно (уже делает `delete table` + `add table` + add rules — расширить до «build new table name, swap, delete old»); для iptables — строить новую chain сначала, затем атомарно swap jump.

### Модуль / Файл: `core/routing/nftset_backend.py`
Количество задач: 1

- [x] **MR-120** 🟠 [MEDIUM] `setup_ui.js` — native `confirm()` для destructive uninstall
  - **Описание:** `if (!confirm('Удалить ${opts.binaryLabel}?')) return;` — native `confirm()` для destructive uninstall sing-box/mihomo/usque binary.
  - **Действие:** Использовать styled modal с существующим `.modal-overlay` class. Include consequence («будут остановлены туннели X, Y») и confirm button, визуально distinct (red).

### Модуль / Файл: `core/singbox_manager.py`
Количество задач: 2

- [x] **MR-19** 🟠 [MEDIUM] Все `_pid_alive` — PID reuse risk
  - **Описание:** `_pid_alive(pid)` делает `os.kill(pid, 0)` и трактует любой non-`ProcessLookupError` как «жив». На Entware/Keenetic PID-реcайклинг агрессивен на занятых роутерах (множество короткоживущих `ip`, `iptables`, `ss` subprocess'ов из самого этого кода). Если туннель-демон умирает и его PID реиспользуется другим процессом в окне до `stop()`, `os.kill(pid, SIGTERM)` убьёт неродственный процесс. Fallback `os.path.exists("/proc/%d" % pid)` делает хуже — возвращает True для ЛЮБОГО существующего PID, даже если это другой бинарник.
  - **Действие:** Перед signal'ом проверять `/proc/<pid>/cmdline` на ожидаемое имя бинарника. Сохранять start time (`/proc/<pid>/stat` field 22) рядом с PID при спавне и сравнивать перед kill.

- [x] **MR-93** 🟠 [MEDIUM] `singbox_manager._do_down` / `mihomo_manager._do_down` — 5s busy-wait вместо `proc.wait(timeout)`
  - **Описание:** Все три используют busy-wait loop:
```python
for _ in range(50):
    if not _pid_alive(pid): break
    time.sleep(0.1)
```
50 iterations × 0.1s = 5s worst case. Каждая итерация fork'ает `/proc/<pid>`-доступ (fallback `_pid_alive` на строке 112 вызывает `os.path.exists`). На MIPS каждый `/proc` stat ~5-10ms; total 250-500ms CPU только на polling. `subprocess.Popen.wait(timeout=5)` делает то же в kernel без busy-loop'а.
  - **Действие:** Держать `Popen` object (не только PID) и использовать `proc.wait(timeout=5)`. Falls through к `proc.kill()` на `TimeoutExpired`.

### Модуль / Файл: `core/singbox_transparent.py`
Количество задач: 1

- [x] **MR-37** 🔴 [HIGH] TPROXY `mark=1` и `table=100` коллидируют с routing-manager'ом
  - **Описание:** ```python
DEFAULT_TPROXY_MARK  = 1
DEFAULT_TPROXY_TABLE = 100
```
`RoutingManager.table_id_for(ifname)` возвращает `100 + (hash % 900)` — диапазон 100-999. Если любой AWG/WG interface name хэшируется ровно в 100 (например короткие имена типа `wg0`), sing-box TPROXY-table и routing-rule-table clash. Также `mark=1` — самый частый fwmark в Linux-экосистеме (используется многими VPN-тулами, conntrack, systemd-networkd) — любой другой процесс, ставящий mark=1, засосёт трафик в TPROXY `ip rule fwmark 1 lookup 100`.
  - **Действие:** Зарезервировать высокий, настраиваемый mark (например `0xfeed0001`) и table вне 100-999 (например `0x100`). Per-instance overridable из settings.

### Модуль / Файл: `core/singbox_watchdog.py`
Количество задач: 1

- [x] **MR-79** 🟠 [MEDIUM] `mihomo_watchdog` / `singbox_watchdog` — serial probing N configs может превысить `check_interval_sec`
  - **Описание:** `_tick()` итерирует `configs` и вызывает `probe_proxy()` сериально, каждый с `http_to = timeout_ms/1000 + 3.0` (default 8s). С 5 mihomo-configs и медленным proxy один tick занимает 40s — overlapping next 60s tick. Previous tick's `_probe_fails` мутация может race'иться с next tick's read.
  - **Действие:** Параллелить через small thread pool, или cap total probe budget per tick.

### Модуль / Файл: `core/strategy_scanner.py`
Количество задач: 3

- [x] **MR-11** 🔴 [CRITICAL] `strategy_scanner._filter_by_dpi` отбрасывает все trick-стратегии
  - **Описание:** Фильтр требует `--filter-l7=tls` AND `tls_client_hello` как подстроки в args:
```python
DPI_FILTERS = {
    "tls_dpi": {"must_have": ["filter-l7=tls", "tls_client_hello"], ...},
    ...
}
if must_have and not any(kw in args_str for kw in must_have):
    continue   # <-- стратегия выбрасывается
```
Но:
1. **Trick-стратегии** (`basic/advanced/direct`) содержат только `--lua-desync=...` в `entry.args` — `--filter-l7=tls --payload=tls_client_hello` инжектируется позже в `_wrap_trick_args()` (строка 1087). На момент фильтрации их нет → `must_have` отбрасывает их. Сканер теряет **весь** trick-каталог для `tls_dpi`/`clienthello_dpi`/`tcp_reset`/`tcp_16_20`/`quic_block`/`http_inject`.
2. Если `blockcheck._aggregate_dpi` неправильно классифицирует (см. ISSUE-062) — например вернёт `quic_block` для HTTP-only блокировки — `must_have=["filter-l7=quic", "quic_initial"]` отбрасывает все TLS-стратегии, сканер возвращает «0 стратегий», auto-remediation поднимает ненужный туннель.
  - **Действие:** Либо (a) запускать `_filter_by_dpi` **после** `_build_strategy_args` (post-wrap, когда trick args содержат реальный filter-l7), либо (b) фильтровать по полю `protocol`/`level` каталог-записи, а не по подстроке сырых args, либо (c) сделать `must_have` опциональным если args содержит `--lua-desync=` (это trick, который будет обёрнут).

- [x] **MR-74** 🟠 [MEDIUM] `strategy_scanner.get_working_strategies()` возвращает list без copy
  - **Описание:** ```python
def get_working_strategies(self) -> list[dict[str, Any]]:
    return [r.to_dict() for r in self._results if r.success]
```
Читает `self._results` без lock. Тем временем `_run_scan` (строки 437-438) аппендит в `self._results` под lock, а `_build_report` (строка 1808) вызывает `self._results.sort(key=...)` **без** lock. Если UI-poll попадёт во время sort, пользователь видит reordered/partial list. Та же проблема в `apply_strategy` (строка 304) и `apply_strategy_by_id` (строка 326).
  - **Действие:** Брать `self._lock` вокруг read, или copy-then-filter pattern.

- [x] **MR-85** 🟠 [MEDIUM] `strategy_scanner._save_resume_state` пишет `/tmp/...` после КАЖДОЙ стратегии
  - **Описание:** С 30 стратегиями в quick mode → 30 writes per scan, 80 в standard, ~150 в full. На Entware `/tmp` — tmpfs (RAM), так что flash wear нет — но на некоторых MIPS-девайсах `/tmp` может быть real filesystem на flash. Path захардкожен без override.
  - **Действие:** Использовать `tempfile.gettempdir()` (уважает `TMPDIR`). Throttle writes до каждых 5 стратегий или каждых 10s.

### Модуль / Файл: `core/strategy_state.py`
Количество задач: 1

- [x] **MR-84** 🔴 [HIGH] `strategy_state._rewrite_locked` пишет state.tsv на каждый `clear_host`
  - **Описание:** ```python
def _rewrite_locked(path: str, entries: list):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(_serialize(entries))
    os.rename(tmp, path)
```
Плюс `healthcheck._tick()` (строки 363-366) вызывает `strategy_state.clear_host(host)` для каждого host'а каждой failing service каждый `interval_min` (default 5 min). На занятом роутере с 5 services × 3 hosts каждый — до 15 writes per 5-min interval = 4 320 writes/day. Каждый write маленький, но flash write-amplification на дешёвом NAND может умножить это в 10-100×.
  - **Действие:** Использовать `safe_io.atomic_write_text()` (уже есть в repo). Важнее — батчить resets across services в рамках одного tick'а (писать файл один раз per tick, не один раз per host), и min-interval debounce (skip если last clear был <60s назад).

### Модуль / Файл: `core/tunnel_monitor.py`
Количество задач: 2

- [x] **MR-21** 🟠 [MEDIUM] `tunnel_monitor` не мониторит sing-box / mihomo
  - **Описание:** Для sing-box код делает `ifaces.add(c.get("tun_iface", ""))` — но `SingboxManager.list_configs` возвращает dict'ы с ключами `name, path, size, mtime, running` — **поля `tun_iface` нет**. То же для `MihomoManager.list_configs`. Так что `c.get("tun_iface", "")` всегда возвращает `""`, а `ifaces.discard("")` на строке 145 его выкидывает. Sing-box и mihomo тихо исключаются из мониторинга.
  - **Действие:** Парсить sing-box/mihomo config (JSON/YAML) для поиска `inbounds[].tag=tun-in`-интерфейса, либо запрашивать бинарник (sing-box имеет clash-api; mihomo экспонирует `/traffic` на controller'е). Как минимум, добавить `tun_iface`-поле в `list_configs()` через парсинг сохранённого config-файла.

- [x] **MR-92** 🟠 [MEDIUM] `tunnel_monitor.get_metrics()` держит `_lock` во время полного computation
  - **Описание:** `get_metrics()` берёт `self._lock` и для каждого interface выполняет list-comprehensions, slicing, divisions. С большим числом interfaces blocks `_collect()` от append'а.
  - **Действие:** Snapshot `self._history` под lock (shallow copy), compute outside lock.

### Модуль / Файл: `core/tunnel_optimizer.py`
Количество задач: 3

- [x] **MR-04** 🔴 [CRITICAL] `tunnel_optimizer.py` — 4 из 6 оптимизаций пишут в несуществующие sysctl-пути
  - **Описание:** Все четыре функции пишут в пути вида `/proc/sys/net/ipv4/conf/<iface>/tcp_rmem_max`, `/proc/sys/net/ipv4/conf/<iface>/tcp_fastopen`, `/proc/sys/net/ipv4/conf/<iface>/tcp_nodelay`, `/proc/sys/net/ipv4/conf/<iface>/tcp_keepalive_time`. **Таких sysctl-узлов в Linux не существует.** TCP sysctl'ы (`tcp_rmem`, `tcp_wmem`, `tcp_fastopen`, `tcp_keepalive_time`, и т.д.) — **глобальные**, лежат в `/proc/sys/net/ipv4/tcp_*`, без префикса `conf/<iface>/`. Проверка `os.path.isfile(path)` всегда возвращает `False`, ничего не пишется.
  - **Действие:** Писать в глобальные `/proc/sys/net/ipv4/tcp_rmem_max`, `tcp_wmem_max`, `tcp_fastopen`, `tcp_keepalive_time` и т.д. С резервным копированием предыдущих значений (см. ISSUE-005). Per-interface тюнинг через sysctl невозможен — потребовалось бы `tc qdisc` или `setsockopt()` в самом бинарнике туннеля.

- [x] **MR-05** 🔴 [CRITICAL] BBR применяется глобально без backup/restore/persistence
  - **Описание:** `_optimize_congestion` пишет `bbr` в `/proc/sys/net/ipv4/tcp_congestion_control` — **глобальный** sysctl, влияющий на каждый сокет роутера (WAN, LAN, Wi-Fi, dnsmasq upstream, web GUI). Предыдущее значение читается (строка 143), но **не сохраняется**. Функции `restore()` нет. То же касается `tcp_fastopen=3` и `tcp_keepalive_time=10`. Настройка не переживает ребут. Вызывается из `usque_manager.start:217` и `warp_in_warp._setup_routes:286` на каждый старт туннеля.
  - **Действие:** ```python
# Опционально сохранять предыдущие значения
prior = open(bbr_path).read().strip()
self._backup[iface] = {"tcp_congestion_control": prior, ...}
# persist в /opt/etc/zapret-gui/state/sysctl-backup.json
# expose restore_iface(iface) + вызывать из manager.stop()
# добавить init-скрипт S99 для повторного применения на boot
```
Лучше: вообще не трогать global CC, а использовать per-route `ip route change ... initcwnd` / `congctl`, либо `SO_MAX_PACING_RATE` через socket options в самом туннель-бинарнике.

- [x] **MR-88** 🟠 [MEDIUM] `tunnel_optimizer._optimize_congestion` — `modprobe` может не существовать на Entware
  - **Описание:** ```python
subprocess.run(["modprobe", "tcp_bbr"], capture_output=True, timeout=5)
```
Entware не ship'ит `kmod`/`modprobe` по умолчанию. На OpenWrt-based системах kernel modules грузятся через `insmod` с full path, или уже built-in. `subprocess.run` райзнет `FileNotFoundError`, которое ловится surrounding `except Exception` и report'ится как «BBR модуль не загружен». Пользователь видит BBR как failed, когда он может быть available как built-in.
  - **Действие:** Сначала `modprobe`, fall back на `insmod /lib/modules/$(uname -r)/tcp_bbr.ko`, затем check `/proc/sys/net/ipv4/tcp_available_congestion_control` на `bbr` независимо от того, как мы туда добрались.

### Модуль / Файл: `core/update_checker.py`
Количество задач: 3

- [x] **MR-49** 🟡 [LOW] `update_checker._check_tgproto` хардкодит `has_update: False`
  - **Описание:** ```python
"has_update": False,  # z2k не имеет семантических версий
```
Запись tgproto в UI никогда не покажет «update available», даже когда `latest != current`.
  - **Действие:** Либо убрать entry, либо корректно вычислять `has_update`.

- [x] **MR-77** 🟠 [MEDIUM] `update_checker._github_latest` shell'ит `curl` вместо `urllib`
  - **Описание:** Каждый `_github_latest` fork'ает `curl` (4× per `check_all()`). `curl` — 1+ MB binary; forking 4× потребляет RAM и CPU. Python stdlib `urllib.request` делает то же без fork'а.
  - **Действие:** Использовать `urllib.request.urlopen` с timeout, парсить JSON in-process.

- [x] **MR-87** 🟡 [LOW] `update_checker` first iteration сразу запускает `check_all()` на boot
  - **Описание:** На boot daemon мгновенно fire'ит 9 GitHub API calls до того, как WAN роутера может быть up. Result: 9 × 15s timeouts = 135s blocked daemon thread, затем 24h sleep. Если WAN поднимается на 30s — следующая проверка через 23h 59min — пользователь видит «no updates» почти сутки.
  - **Действие:** Initial wait 60-120s перед первым `check_all()` (как `healthcheck._loop` строка 211: `self._stop_evt.wait(30)`).

### Модуль / Файл: `core/usque_manager.py`
Количество задач: 8

- [x] **MR-122** 🟠 [MEDIUM] Многопроцессный доступ к Thread-based Singleton менеджерам (Решено/Архитектурный инвариант)
  - **Описание:** Использование Double-Checked Locking синглтонов с Threading Lock сломается в multiprocessing.
  - **Действие:** НЕ ТРЕБУЕТСЯ / WONTFIX. Архитектура проекта (см. CoderManual) гарантирует запуск бэкенда Bottle в однопроцессном многопоточном режиме через собственный ThreadedWSGIServer. Пул процессов не используется, поэтому стандартная потокобезопасная реализация get_xxx_manager() с threading.Lock() является корректной и достаточной.

- [x] **MR-124** 🟡 [LOW] Отсутствие аннотаций типов (Type Hints) в новых модулях
  - **Описание:** В новых модулях отсутствуют аннотации типов для параметров и возвращаемых значений.
  - **Действие:** Добавить аннотации типов во все публичные методы и функции новых менеджеров.

- [x] **MR-126** 🟠 [MEDIUM] Избыточный запуск subprocess `ip link show` в `_check_iface_up()`
  - **Описание:** Для проверки работоспособности интерфейса метод `_check_iface_up` запускает subprocess.
  - **Действие:** Читать статус из `/sys/class/net/<iface>/operstate` or `/sys/class/net/<iface>/carrier` без форка процесса.

- [x] **MR-13** 🔴 [HIGH] Все tunnel managers: `start()` race condition
  - **Описание:** Все три менеджера проверяют `if self._is_running(...)` **без** `self._lock`, затем вызывают `subprocess.Popen(...)` **без** lock, и только потом кратко берут lock для вставки proc в dict:
```python
if self._is_running(iface): return ...
proc = subprocess.Popen(cmd, ..., start_new_session=True)   # нет lock
with self._lock:                                            # строка 211
    self._processes[iface] = proc
```
Два HTTP-потока, одновременно вызывающих `start()` для того же iface, оба проходят `_is_running`-проверку (возвращает False, т.к. никто ещё не вставил), оба спавнят Popen (один биндит TUN-устройство/порт; второй молча фейлится или конфликтует), и proc второго перетирает первый в dict — первый Popen-объект GC'ится, его child становится orphan'ом.
  - **Действие:** Брать `self._lock` на всю проверку `_is_running` + `Popen` + dict-insert (как `singbox_manager._do_up:484-485`: `with self._lock: return self._do_up(name)`). Или использовать per-iface `threading.Lock` для распараллеливания разных iface, но сериализации того же.

- [x] **MR-137** 🟠 [MEDIUM] Накопление процессов-зомби при остановке туннелей без ожидания wait()
  - **Описание:** После вызова `proc.kill()` или `SIGKILL` менеджеры не вызывают `proc.wait()`.
  - **Действие:** Всегда вызывать `proc.wait()` или `proc.communicate()` после завершения дочернего процесса.

- [x] **MR-14** 🔴 [HIGH] Все tunnel managers: нет `os.killpg` несмотря на `start_new_session=True`
  - **Описание:** Каждый менеджер спавнит с `start_new_session=True` (создавая новую process group/session), затем убивает через `proc.send_signal(signal.SIGTERM)` или `os.kill(pid, signal.SIGTERM)` — только parent PID. `os.killpg` нигде не используется, кроме `core/blockcheck2.py:347, 357`.
  - **Действие:** ```python
try:
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
except ProcessLookupError:
    pass
# И SIGKILL аналогично через os.killpg
```

- [x] **MR-146** 🟡 [LOW] Объявленный, но не используемый регулярный экспрешн `_VALID_IFACE_RE`
  - **Описание:** Регулярное выражение `_VALID_IFACE_RE` объявлено, но не применяется при запуске/остановке интерфейсов.
  - **Действие:** Добавить вызов `_VALID_IFACE_RE.match(iface)` in методах `start()` и `stop()`.

- [x] **MR-25** 🟠 [MEDIUM] `usque_manager.stop` fallback — хардкод `0.5s` между SIGTERM и SIGKILL
  - **Описание:** Когда Popen-объекта нет в `_processes` (например, GUI перезапустили после старта туннеля), fallback делает:
```python
os.kill(pid, signal.SIGTERM)
time.sleep(0.5)
os.kill(pid, signal.SIGKILL)
```
0.5s произвольно. Если SIGTERM хватает за 10ms — 490ms потеряны. Если SIGTERM требует 2s (usque flush'ит сессии) — SIGKILL стреляет во время cleanup, возможно оставляя TUN-устройство orphan'ом. Также нет `try/except ProcessLookupError` — если процесс вышел между sleep и SIGKILL (ожидаемый случай).
  - **Действие:** Poll-loop с 100ms интервалом до 3s, затем SIGKILL. Проверять `proc.poll() is not None` перед SIGKILL. Явно вызывать `ip link delete dev <iface>` в stop() как belt-and-suspenders cleanup.

### Модуль / Файл: `index.html`
Количество задач: 2

- [x] **MR-108** 🟠 [MEDIUM] SVG mini-chart фиксированной ширины 200px
  - **Описание:** `_renderMiniChart` производит `<svg width="200" height="40" style="display:block;">` — **фиксированная 200px ширина, нет `viewBox`, нет `preserveAspectRatio`**. На 360px-wide телефоне две cards side-by-side в `.card-body` (строка 89: `display:flex; gap:24px; flex-wrap:wrap;`) collapse, но SVG остаётся 200px.
  - **Действие:** `<svg viewBox="0 0 200 40" preserveAspectRatio="none" width="100%" height="40">` или использовать существующий `sparkline.js` component (уже загружен в `index.html:120`).

- [x] **MR-119** 🟠 [MEDIUM] Bundle ~1.68 MB без minification / code-splitting
  - **Описание:** Total uncompressed ~1.68 MB (CSS ~200 KB + JS ~1.48 MB). No minification, no ES modules, no dynamic `import()`, no tree-shaking. Все 36 page modules загружаются upfront через 50 `<script>` tags в `index.html`. Largest modules: `strategies.js` (139 KB), `singbox_configs.js` (79 KB), `help.js` (74 KB), `settings.js` (61 KB), `routing_unified.js` (58 KB).
  - **Действие:** Мигрировать на ES modules + bundler (esbuild/vite) с code-splitting per route. Lazy-load heavy pages (`strategies`, `singbox_configs`, `help`) через dynamic `import()`. Expected bundle reduction на first paint: с 1.68 MB до <300 KB.

### Модуль / Файл: `settings.json`
Количество задач: 2

- [x] **MR-78** 🟠 [MEDIUM] Watchdog'и читают `settings.json` с flash на каждой итерации
  - **Описание:** `_run_loop` вызывает `_get_settings()["check_interval_sec"]` каждые 30s (default). `_get_settings()` вызывает `get_config_manager().load()` — read + parse `settings.json` с `/opt/.../settings.json` (flash) на каждый call.
  - **Действие:** Кешировать settings с TTL (например 5 min) или subscribe to config-change events.

- [x] **MR-82** 🟠 [MEDIUM] `dns_routing.add_rule` — save config на каждое правило; нет batch API
  - **Описание:** ```python
def add_rule(self, domain, dns_server, description=""):
    rules.append({...})
    cm.set("dns_routing", "rules", rules)
    cm.save()    # <-- full config.json rewrite
```
Добавление 1000 правил = 1000 rewrites всего `settings.json`. Плюс `apply()` (строка 97) затем пишет `dns-routing.conf`. С dnsmasq `server=/domain/IP` директивы scale'ятся линейно; 1000+ правил meaningfully замедляют dnsmasq startup и per-query lookup.
  - **Действие:** Добавить `add_rules_batch(rules: list[dict])` — берёт lock один раз, модифицирует list, save'ит один раз. Документировать разумный upper bound (~5000 rules) и warning'уть пользователя.

### Модуль / Файл: `setup_ui.js`
Количество задач: 1

- [x] **MR-101** 🔴 [HIGH] `usque_setup.js` — статический HTML, не использует `SetupUI`
  - **Описание:** `UsqueSetupPage` — **просто статический HTML с `<pre><code>curl ...</code></pre>`** — нет install button, нет environment check, нет progress bar. Полностью несовместимо с `singbox_setup.js`, `mihomo_setup.js`, `awg_setup.js`, которые все используют unified `SetupUI.create({...})` component (см. `setup_ui.js:93-427`) с: environment card, binary version card с «установлено X / в релизе Y» comparison, install/update/uninstall buttons с progress, install-from-file upload, architecture picker.
  - **Действие:** Конвертировать `UsqueSetupPage` в `SetupUI.create({ globalName:'UsqueSetupPage', apiBase:'/api/usque', binaryLabel:'usque', ... })`, mirroring `mihomo_setup.js`. Backend `/api/usque/install` уже существует (см. `usque.js:184-197`).

### Модуль / Файл: `tests/`
Количество задач: 1

- [x] **MR-121** 🟠 [MEDIUM] Дефицит тестового покрытия (mocking, отсутствие интеграционных тестов)
  - **Описание:** Тесты в проекте проверяют исключительно happy path с использованием избыточного мокинга, скрывающего реальные проблемы интеграции компонентов.
  - **Действие:** Внедрить полноценные интеграционные тесты с использованием реальных/эмулированных сетевых интерфейсов, покрыть тестами логику автозапуска и восстановления служб.

### Модуль / Файл: `uninstall.sh`
Количество задач: 1

- [x] **MR-12** 🔴 [CRITICAL] `teardown.py` неполный — оставляет routing/ipset/nftset/dnsmasq/NDMS осиротевшими
  - **Описание:** ```python
def run():
    _disable_autostart()
    _stop_nfqws()
    _remove_firewall()           # только NFQUEUE rules
    _remove_persistence()
    _stop_engines()
    _remove_transparent()        # только sing-box transparent
    return 0
```
**Отсутствует:** нет `RoutingManager.remove_rule()` для сохранённых CIDR/domain/device/DSCP правил; нет `nftset_backend.destroy_set()` / `ipset_backend.destroy_set()`; нет cleanup `dnsmasq_integration` (managed file + include marker); нет `masquerade.remove_if_unused()`; нет `ndms_backend.remove_*_rule()`; нет удаления `AWG_ROUTING_PRE/OUT/NAT` iptables-цепок или `awg_routing` nft-таблицы.
  - **Действие:** Добавить `_remove_routing()`, который итерирует `storage.load_rules()` и вызывает `_remove(rule)` для каждого, затем удаляет managed dnsmasq-файл + include marker, затем `nft delete table inet awg_routing`, `iptables -t mangle/nat -X AWG_ROUTING_*`, и NDMS-side `delete_*` для всех `ZGUI_*`-объектов.

### Модуль / Файл: `usque_manager.py`
Количество задач: 2

- [x] **MR-01** 🔴 [CRITICAL] WARP-in-WARP падает с `AttributeError` на каждом запуске
  - **Описание:** Код читает `self._outer_proc = mgr._process` после успешного `usque_mgr.start(...)`. Но `UsqueManager` определяет только `self._processes` (dict, `usque_manager.py:33`) — атрибута `_process` не существует. Все 4 точки (`_start_masque_masque`, `_start_masque_awg`, `_start_awg_masque` и т.д.) поднимут `AttributeError`. Ни `try/except`, ни тестов на эти пути нет (`tests/` содержит только `test_warp_importer.py` / `test_warp_generator.py`).
  - **Действие:** Либо `UsqueManager.start` должен возвращать `Popen`-хендл, либо добавить accessor `get_process(iface)`. В `warp_in_warp` использовать PID из `{"ok": True, "pid": ...}` и `_is_running(iface)` для проверки живости.
```python
# usque_manager.py
def start(self, iface, **kwargs) -> dict:
    ...
    return {"ok": True, "pid": proc.pid, "process": proc}
# warp_in_warp.py
res = usque_mgr.start(...)
if res.get("ok"):
    self._outer_proc = res.get("process")  # вместо mgr._process
```

- [x] **MR-45** 🟠 [MEDIUM] `tunnel_optimizer._optimize_mtu` перетирает AWG-configured MTU
  - **Описание:** `_optimize_mtu` вызывает `ip link set iface mtu <1420|1280|1500>` на основе `profile` аргумента, ИГНОРИРУЯ MTU, установленный туннель-демоном. `awg_manager._do_up:1031-1033` ставит MTU из .conf пользователя (`iface.get("MTU")`), который для WARP-in-WARP должен быть 1280 (nested tunnels). Затем `warp_in_warp._setup_routes:286` вызывает `optimize_iface(inner_iface, "balanced")` → форсит 1420. Для WireGuard/AWG 1420 + 80 (WG header) = 1500 → фрагментация на outer tunnel. Profile «throughput» (1500) — ещё хуже, гарантированная фрагментация.
  - **Действие:** Не трогать MTU в `tunnel_optimizer` вообще — туннель-демон знает свой overhead. Если тюнинг нужен, только снижать MTU (никогда не повышать выше того, что поставил демон), и только для outer tunnel.

### Модуль / Файл: `vendor/bottle.py`
Количество задач: 2

- [x] **MR-54** 🔴 [HIGH] `bottle.py` 0.13.4 — dev-branch, не для production
  - **Описание:** `__version__ = '0.13.4'`. Линейка 0.13 — unstable; stable — 0.12.x. Changelog предупреждает «0.13 is in development». Старые 0.13.x-snapshot'ы несли CRLF-header bugs. Исторические CVE на bottle: CVE-2014-3137 (open redirect, fixed 0.12.x), CVE-2016-9964 (CRLF injection, fixed 0.12.11), CVE-2022-31721 (ReDoS in router, fixed 0.12.20). Публичных CVE именно против 0.13.4 на момент аудита нет, но сам dev-branch статус — риск.
  - **Действие:** Пинить к latest 0.12.x для production.

- [x] **MR-64** 🔴 [HIGH] `_install_upload` — нет size limit / нет extension whitelist
  - **Описание:** `app.py:30` ставит только `BaseRequest.MEMFILE_MAX = 16 MiB` (bounding `request.json`, **не** multipart). Bottle's multipart parser (`vendor/bottle.py:3397`) spill'ит в temp file, но не reject'ит. `make_workdir()` default'ит в `/tmp` (tmpfs, обычно 32-128 MB на Entware). Любое расширение принимается.
  - **Действие:** Hard-cap `Content-Length` ≤ 64 MB в `before_request` hook для upload-роутов; whitelist `(.bin, .tar.gz, .tgz, .zip)`; per-IP rate-limit; sanitize filename.

### Модуль / Файл: `web/css/style.css`
Количество задач: 5

- [x] **MR-102** 🟠 [MEDIUM] Touch targets ниже WCAG 44×44px
  - **Описание:** Touch-target sizing для `@media (pointer: coarse)`: `.btn { min-height: 40px }`, `.btn-sm { min-height: 36px }`, `.nav-item { min-height: 44px }`. WCAG 2.5.5 (Target Size, Level AAA) и upcoming WCAG 2.2 SC 2.5.8 (Level AA) требуют **44×44 CSS px** minimum. `.btn-sm` на 36px — значительно ниже.
  - **Действие:** Bump `.btn-sm { min-height: 40px }` и `.btn { min-height: 44px }` под `pointer: coarse`.

- [x] **MR-103** 🟠 [MEDIUM] Нет `@media (prefers-reduced-motion: reduce)`
  - **Описание:** Нет `@media (prefers-reduced-motion: reduce)` rule. CSS использует multiple infinite animations: `.status-dot.running` pulses (строка 668), `@keyframes pulse-green` (674), `.spinner` (686), `.control-status-ring` (855). Для пользователей с vestibular disorders blinking/pulsing — harmful.
  - **Действие:** ```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
  }
}
```

- [x] **MR-104** 🟠 [MEDIUM] Contrast ratios для muted text fail WCAG AA
  - **Описание:** Contrast ratios для muted text fail WCAG AA (4.5:1) для normal text. Dark theme: `--text-muted: #565a6e` на `--bg-card: #1a1d28` ≈ 3.0:1. Light theme: `--text-muted: #8990a1` на `--bg-card: #ffffff` ≈ 3.4:1. Muted text используется heavily в `.detail-row`, `.text-muted` labels, log timestamps, form hints.
  - **Действие:** Darken muted text до `#7a7f96` (≈ 4.6:1) и light-theme до `#6a7184` (≈ 4.6:1).

- [x] **MR-106** 🟠 [MEDIUM] Нет `:focus-visible` на buttons
  - **Описание:** Нет `:focus-visible` rule для buttons / nav items / tabs. `input:focus` (строка 173) и `.form-input:focus` (1347) получают `box-shadow`, но `.btn`, `.nav-item`, `.tab-btn` — без visible focus indicator. Browsers fall back to default outline, который многие CSS resets strip'ают.
  - **Действие:** ```css
.btn:focus-visible, .nav-item:focus-visible, .tab-btn:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
```

- [x] **MR-107** 🟠 [MEDIUM] Modals не full-screen на mobile
  - **Описание:** Modals на 768px получают `max-height: calc(100dvh - 20px)`, но **не** forced full-screen на mobile. Нет `max-width: 100vw` или `inset: 0` rule, форсящего full-screen takeover на телефонах.
  - **Действие:** На `@media (max-width: 480px)` force `.modal-content { width: 100vw; height: 100dvh; max-height: 100dvh; border-radius: 0; }`.

### Модуль / Файл: `web/index.html`
Количество задач: 2

- [x] **MR-105** 🟠 [MEDIUM] Нет skip-link для keyboard users
  - **Описание:** Нет `<a href="#content" class="skip-link">Перейти к содержимому</a>` для keyboard users. Sidebar имеет 30+ nav items; tabbing through them на каждом page load — tedious.
  - **Действие:** Добавить visually-hidden skip-link как первый child `<body>`, revealed on focus.

- [x] **MR-71** 🟡 [LOW] `var` в index.html
  - **Описание:** `var _t = localStorage.getItem('zapret-gui-theme');` — использует `var` (function-scoped, hoisted). Все остальные файлы корректно используют `const`/`let`.
  - **Действие:** Заменить на `const _t = ...`.

### Модуль / Файл: `web/js/api.js`
Количество задач: 1

- [x] **MR-91** 🔴 [HIGH] `web/js/api.js` — `fetch()` без `AbortController` и без timeout
  - **Описание:** `fetch()` без `AbortController` и без timeout. Если backend hang'нёт (например на GitHub version check, что comments в `setup_ui.js:163` признают может занять «tens of seconds»), UI ждёт forever.
  - **Действие:** Добавить `signal: AbortSignal.timeout(15000)`. Expose per-request timeout option. Surface timeout errors как `Toast.error("Таймаут запроса")`.

### Модуль / Файл: `web/js/components/sidebar.js`
Количество задач: 1

- [x] **MR-116** 🟡 [LOW] Sidebar не trap'ит фокус на mobile
  - **Описание:** Когда mobile sidebar открывается, focus не move'ится в sidebar и не trap'ится. Escape handler (строки 269-274) зарегистрирован, но нет `inert` на main content, нет focus management.
  - **Действие:** На `_setOpen(true)`, set `main#content` `inert` до close, и move focus на sidebar's first focusable item. На close, return focus на burger.

### Модуль / Файл: `web/js/components/toast.js`
Количество задач: 2

- [x] **MR-115** 🟡 [LOW] Toast — нет max limit, нет dedup
  - **Описание:** Нет maximum toast limit. Если 20 errors fire в rapid succession (например 20 polling failures), 20 toast'ов stack vertically. Они auto-dismiss после 4s (`DURATION = 4000`), но multiple всё равно pile up.
  - **Действие:** Cap до 3 visible; если 4th arrives — drop oldest. Same-message dedup (не показывать 10 «Сервер недоступен» подряд).

- [x] **MR-67** 🔴 [HIGH] Нет `aria-live` на toast
  - **Описание:** Toast container и индивидуальные toast'ы не имеют `role="alert"` / `aria-live="polite"`. `Toast.error(...)` невидим для screen readers.
  - **Действие:** Добавить `aria-live="polite"` на `#toast-container` и `role="alert"` на `.toast.error` / `.toast.warning` (`role="status"` на `.toast.success` / `.toast.info`).

### Модуль / Файл: `web/js/pages/block_detector.js`
Количество задач: 1

- [x] **MR-118** 🟡 [LOW] `block_detector._timeAgo` — смешение Latin и Cyrillic
  - **Описание:** `_timeAgo` возвращает строки типа `"5s назад"`, `"12m назад"`, `"3h назад"`, `"2d назад"` — mixing Latin time-unit letters (s/m/h/d) с Russian словом «назад». Также нет localisation unit words.
  - **Действие:** Либо полностью Russian («5 сек назад», «12 мин назад»), либо полностью English («5s ago»); и route через `I18n.t()`.

### Модуль / Файл: `web/js/pages/dashboard.js`
Количество задач: 1

- [x] **MR-131** 🟡 [LOW] Информационный шум на Dashboard из-за пустых карточек служб
  - **Описание:** Dashboard отображает 11 фиксированных карточек статуса, даже если службы отключены.
  - **Действие:** Скрывать карточки неактивных/неустановленных служб или группировать их в компактную панель состояния.

### Модуль / Файл: `web/js/pages/dns_routing.js`
Количество задач: 2

- [x] **MR-149** 🔴 [CRITICAL] Хранимая XSS-уязвимость (Stored XSS) через одинарные кавычек в инлайн JS
  - **Описание:** Функция esc() экранирует только HTML-теги. Внедрение одинарной кавычки позволяет выполнить произвольный JS.
  - **Действие:** Отказаться от инлайн-обработчиков событий, навешивая слушатели динамически через addEventListener.

- [x] **MR-68** 🔴 [HIGH] `<label>` не ассоциированы с `<input>`
  - **Описание:** Все `<label>` — bare: `<label>Режим</label> <select id="tgproxy-engine">…</select>`. Labels не ассоциированы с inputs — нет `for=`-атрибута и нет обёртки input'а внутри label.
  - **Действие:** Либо `<label for="tgproxy-engine">Режим</label>` + `<select id="tgproxy-engine">`, либо wrap: `<label>Режим <select …></label>`.

### Модуль / Файл: `web/js/pages/opera_proxy.js`
Количество задач: 1

- [x] **MR-111** 🟠 [MEDIUM] Нет client-side form validation на tunnel-страницах
  - **Описание:** Нет client-side validation на form fields. `_saveConfig()` (tgproxy:194) отправляет что есть в inputs без проверки port range, secret format (hex), domain validity, URL format. Только validation — «is there a value» в `warp_in_warp.js:267-274`.
  - **Действие:** Добавить inline validation: port 1-65535, hex secret regex `^[0-9a-fA-F]+$`, domain regex, URL regex. Show inline error text под field с `role="alert"`.

### Модуль / Файл: `web/js/pages/tunnel_monitor.js`
Количество задач: 1

- [x] **MR-136** 🟠 [MEDIUM] Утечка всей истории метрик в каждом API запросе Tunnel Monitor
  - **Описание:** Эндпоинт метрик возвращает полную историю измерений за всё время работы.
  - **Действие:** Ограничить размер возвращаемой истории (например, последние 60 точек) на стороне бэкенда.

### Модуль / Файл: `web/js/pages/tunnel_optimizer.js`
Количество задач: 1

- [x] **MR-114** 🟠 [MEDIUM] `tunnel_optimizer.applyAll()` — generic error + no button disable
  - **Описание:** `applyAll()` не disable'ит «Применить ко всем туннелям» button. `Toast.error("Ошибка")` (строка 153) — generic, нет error detail. Также `_renderProfile()` вызывается один раз на render, но `applyAll()` не refresh'ит profile dropdown после apply.
  - **Действие:** Disable button во время request; pass `e.message` to toast; call `_renderProfile()` после success.

### Модуль / Файл: `web/js/pages/update_checker.js`
Количество задач: 1

- [x] **MR-113** 🟠 [MEDIUM] `update_checker._check()` не disable button
  - **Описание:** `_check()` не disable'ит «Проверить обновления» button пока request in-flight. Пользователь может кликать repeatedly, spawning parallel checks.
  - **Действие:** Disable `#uc-btn-check` в начале `_check()`, re-enable в `finally`. Show spinner внутри button.

### Модуль / Файл: `web/js/pages/usque.js`
Количество задач: 4

- [x] **MR-100** 🔴 [HIGH] `usque.js` использует native `prompt()` для имени конфига
  - **Описание:** `_register()` использует `prompt("Имя конфига:", "warp-default")` для имени нового config'а. Native browser prompt — blocking, ugly, mobile-unfriendly, без validation, рендерится inconsistently в разных браузерах. Дополнительно: отсутствие client-side validation chars/length — это та самая дыра, которая позволяет path-traversal (ISSUE-008).
  - **Действие:** Заменить на inline form field на странице (input + button), или modal через существующий `.modal-overlay`. Validate name regex'ом `^[a-zA-Z0-9_-]{1,32}$`. Это fix'ит и UX, и security-баг ISSUE-008.

- [x] **MR-112** 🟠 [MEDIUM] `usque.install()` — нет progress indicator
  - **Описание:** `install()` показывает `Toast.info("Установка usque...")` и затем ждёт `API.post("/api/usque/install")` без progress indicator. Сравните с `setup_ui.js:384-405`, который polls `/install/status` каждые 800ms и render'ит progress bar (строки 80-91).
  - **Действие:** Либо route'нуть usque install через `SetupUI` (см. ISSUE-101), либо реплицировать `startPolling()` / `progressHtml()` pattern из `setup_ui.js:206-222`.

- [x] **MR-69** 🟡 [LOW] Inline `onclick`/`onchange` — блокирует strict CSP
  - **Описание:** Страницы используют `onclick="UsquePage.install()"`, `onchange="${opts.globalName}.onArchChange()"` и т.д. Это форсит каждый page-module быть global'ом и предотвращает CSP `script-src 'self'` (inline handlers требуют `unsafe-inline`).
  - **Действие:** Atach listeners через `addEventListener` после `render()`. Или мигрировать на ES modules с proper imports.

- [x] **MR-99** 🔴 [HIGH] Полностью хардкод-русский UI без i18n-системы
  - **Описание:** `<html lang="ru">` и весь UI захардкожен на русском. Нет translation system, нет string table, нет `data-i18n` attributes. Каждый label, toast, prompt, error string — literal RU string в JS source.
Примеры хардкода:
- `web/js/pages/usque.js:14` — `<h1>WARP / MASQUE</h1>`
- `web/js/pages/usque.js:131` — `Toast.success("WARP-сессия зарегистрирована")`
- `web/js/pages/usque.js:170` — `confirm('Удалить конфиг "${name}"?')`
- `web/js/pages/tgproxy.js:74` — `const text = st.running ? "Работает" : "Остановлен"`
- `web/js/pages/opera_proxy.js:223` — `Toast.success("Настройки сохранены")`
- `web/js/pages/warp_in_warp.js:96` — `const text = st.active ? "Активен" : "Неактивен"`
- `web/js/pages/dashboard.js:235` — `status.textContent = running ? 'Работает' : 'Остановлен'`
- `web/js/pages/block_detector.js:173` — `return diff + "s назад"`
  - **Действие:** Ввести `I18n.t(key)` с `ru.json` / `en.json` dictionary, загружаемым перед `App.init()`. Заменить literals на `data-i18n` attributes в HTML и `I18n.t('…')` calls в JS. Добавить language switcher рядом с theme toggle.

### Модуль / Файл: `web/js/pages/warp_in_warp.js`
Количество задач: 3

- [x] **MR-109** 🟠 [MEDIUM] `warp_in_warp.js` — хардкод default SNI «ozon.ru» / «www.google.com»
  - **Описание:** `<input type="text" id="wiw-outer-sni" placeholder="ozon.ru" value="ozon.ru">` — хардкод **default value** для SNI. Если пользователь просто кликает «Поднять» без изменения, «ozon.ru» отправляется. То же для inner SNI = «www.google.com» (строка 200).
  - **Действие:** Использовать только `placeholder="ozon.ru"` и require от пользователя ввести значение (с inline validation если empty). Или сделать value явно placeholder с empty `value=""`.

- [x] **MR-110** 🟠 [MEDIUM] `warp_in_warp.js` дублирует API-вызовы
  - **Описание:** `_loadConfig` re-fetches `/api/warp-in-warp/status` (строка 143) и `/api/warp-in-warp/detect` (строка 144) — но они **уже fetched** в `_loadStatus` (строка 92) и `_loadDetect` (строка 119) в том же `_refresh()` cycle. Так что каждые 3s страница issue'ит **5 API calls** вместо 3 (status, detect, usque/configs).
  - **Действие:** Кешировать результат `_loadStatus` / `_loadDetect` в module-level variables (`_lastStatus`, `_lastDetect`) и reus'ать в `_loadConfig`.

- [x] **MR-130** 🟡 [LOW] Непонятное для пользователя разграничение 4 режимов WARP-in-WARP
  - **Описание:** В интерфейсе предлагается выбор из 4 режимов WARP-in-WARP, но нет текстовых подсказок.
  - **Действие:** Добавить информативные подсказки (tooltip'ы) для каждого режима в интерфейсе настройки.

### Модуль / Файл: `web/js/pages/{usque,tgproxy,opera_proxy,warp_in_warp,tunnel_monitor,block_detector}.js`
Количество задач: 1

- [x] **MR-90** 🔴 [HIGH] Polling pages не останавливаются на `document.hidden`
  - **Описание:** Все polling-страницы вызывают `setInterval(_refresh, POLL_MS)` (3s для usque/tgproxy/opera/warp_in_warp; 5s для tunnel_monitor/block_detector). `_refresh` issue'ит parallel `await API.get(...)` без AbortController, без in-flight guard, без pause на `document.hidden`.
  - **Действие:** ```js
let inFlight = false;
async function _refresh() {
  if (inFlight) return;
  inFlight = true;
  try { /* ... */ } finally { inFlight = false; }
}
document.addEventListener('visibilitychange', () => {
  if (document.hidden) stopPoll();
  else _startPoll();
});
```