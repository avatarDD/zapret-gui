# Zapret Web-GUI

[![Release](https://img.shields.io/github/v/release/avatarDD/zapret-gui?style=flat-square)](https://github.com/avatarDD/zapret-gui/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/avatarDD/zapret-gui/release.yml?style=flat-square&label=build)](https://github.com/avatarDD/zapret-gui/actions)
[![License](https://img.shields.io/github/license/avatarDD/zapret-gui?style=flat-square)](LICENSE)

Веб-интерфейс для обхода блокировок на роутерах с Entware (Keenetic) и
OpenWrt: **nfqws2** (zapret2), туннели **AmneziaWG / sing-box / mihomo** и
**единый слой маршрутизации** «назначение → метод» поверх них.

Тёмная тема, мобильная адаптация, SPA на vanilla JS + Python/Bottle бэкенд.

## Возможности

- **Управление nfqws2** — запуск/остановка/рестарт с мониторингом процесса
- **Стратегии** — builtin + пользовательские JSON-стратегии, превью команды
- **BlockCheck** — тестирование доступности сервисов, классификация типа DPI
- **Подбор стратегий** — автоматический перебор стратегий из INI-каталогов
- **Домены и IP-списки** — hostlists с нормализацией, ipsets с загрузкой по ASN
- **Блобы** — hex-редактор, генерация fake TLS/HTTP ClientHello
- **Hosts** — управление /etc/hosts с пресетами
- **Диагностика** — ping, HTTP/HTTPS, DNS, проверка конфликтов
- **Логи** — real-time SSE поток
- **Автозапуск** — генерация init-скриптов
- **Обновление GUI** — проверка и обновление из веб-интерфейса
- **Zapret2 installer** — установка/обновление nfqws2 с GitHub
- **AmneziaWG** — туннели (AWG/WG), Cloudflare WARP (импорт/нативная
  генерация/WARP-in-WARP), selective routing по CIDR / доменам /
  устройствам / **DSCP-меткам (QoS)**; **авто-переподключение** туннеля
  при деградации связи (watchdog: handshake-age + активная проба через
  туннель)
- **sing-box / mihomo** — два взаимозаменяемых прокси-движка; для
  sing-box — прозрачное проксирование в режимах **TProxy / Redirect /
  Hybrid** (заворот трафика LAN и самого роутера, DNS-hijack, anti-leak
  IPv6), поднятие fd-лимитов под нагрузкой
- **Подписки и пул серверов** — импорт подписок
  (vmess/vless/trojan/ss/hysteria2/tuic, base64/clash/sing-box JSON) с
  автообновлением по таймеру; **пул из публичных источников** (свалки
  бесплатных ключей) с дедупом, редактируемым списком источников,
  кэшем last-good (пустой ответ не затирает текущие) и обёрткой в
  **urltest** (бесшовное переключение на живой сервер). **Тестер**
  серверов: TCP-отсев + e2e-замер задержки через движок до крупного
  облака (Cloudflare/Amazon), статус каждого сервера
- **Единый слой маршрутизации** — «назначение → метод»: для домена /
  CIDR / списка / geosite выбирается метод (`direct` / `nfqws2` /
  туннель) с резервной цепочкой, авто-мониторингом успешности и
  failover; общие именованные списки доменов/IP
- **CLI** — управление из консоли: `zapret-gui status | nfqws … |
  strategy … | singbox … | mihomo …`
- **Зеркало/оффлайн-установка** бинарников (env `ZAPRET_GUI_MIRROR`
  или `install.mirror` / `file://`) — когда GitHub заблокирован
- **Бэкап/восстановление** — выгрузка всей конфигурации (настройки,
  стратегии, конфиги sing-box/mihomo, hostlist'ы) в один JSON-файл и
  восстановление из него (Настройки → Бэкап)

## Требования

- Python 3.11+ (`python3-light` в Entware)
- Bottle (`opkg install python3-bottle` или `pip3 install bottle`)
- RAM: ~20–25 MB, Flash: ~500 KB (+ python3-light ~5 MB)
- Архитектура: любая (mipsel, arm64, armv7, x86_64, mips, riscv64)

## Установка

### Вариант 1: ipk-пакет (рекомендуется)

**Keenetic (Entware):**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-keenetic.ipk
opkg install zapret-gui-keenetic.ipk
/opt/etc/init.d/S99zapret-gui start
```

**Другие роутеры с Entware (ASUS, Xiaomi, GL.iNet, etc.):**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-entware.ipk
opkg install zapret-gui-entware.ipk
/opt/etc/init.d/S99zapret-gui start
```

**OpenWrt:**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-openwrt.ipk
opkg install zapret-gui-openwrt.ipk
/etc/init.d/zapret-gui start
```

**Linux (tar.gz):**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-linux.tar.gz
tar xzf zapret-gui-linux.tar.gz
cd zapret-gui
pip3 install bottle
python3 app.py --host 0.0.0.0 --port 8080
```

### Вариант 2: Автоустановка скриптом

```bash
wget -O - https://raw.githubusercontent.com/avatarDD/zapret-gui/main/install.sh | sh
```

Скрипт автоматически определит платформу, установит зависимости и запустит GUI.

### Вариант 3: Ручная установка

```bash
cd /opt
git clone https://github.com/avatarDD/zapret-gui.git
cd zapret-gui
opkg install python3-light python3-bottle
python3 app.py --host 0.0.0.0 --port 8080
```

> Если `python3-bottle` не нашёлся в репозитории, поставьте его через pip:
> `opkg install python3-pip && python3 -m pip install bottle`.
> `python3-light` сам по себе не содержит pip.

## Использование

Веб-интерфейс: `http://<IP-роутера>:8080`

### Быстрый старт

1. **Zapret2** → установите nfqws2
2. **Стратегии** → выберите и примените стратегию
3. Или **Подбор стратегий** → автоматический поиск рабочей стратегии
4. **Автозапуск** → включите для работы после перезагрузки
5. **BlockCheck** или **Диагностика** → проверьте доступность
6. Нужны туннели/гибкая маршрутизация? → **AmneziaWG/sing-box/mihomo** +
   страница **Маршрутизация** (для домена/списка выберите метод и
   резервную цепочку)

### Страницы

| Страница | Описание |
|----------|----------|
| Главная | Статус nfqws, текущая стратегия, быстрые действия |
| Управление | Старт/стоп/рестарт, мониторинг процесса |
| Стратегии | Список стратегий, редактор, превью команды |
| Домены | Списки хостов для фильтрации |
| IP-списки | IP-адреса и подсети, загрузка по ASN |
| Блобы | Бинарные данные для fake-пакетов |
| Hosts | Управление /etc/hosts |
| BlockCheck | Тестирование доступности, классификация DPI |
| Подбор стратегий | Автоматический перебор стратегий |
| Zapret2 | Установка/обновление nfqws2 |
| Диагностика | Проверка сервисов, конфликтов, системы |
| Логи | Журнал событий в реальном времени |
| Автозапуск | Управление init-скриптом |
| Настройки | Конфигурация GUI, nfqws, firewall, зеркало, **бэкап/восстановление** |
| AmneziaWG → Setup | Wizard: детект окружения, prerequisites, установка бинарников |
| AmneziaWG → Dashboard | Статус интерфейсов и peer'ов, up/down, autostart |
| AmneziaWG → Configs | Редактор `.conf`, импорт/экспорт, валидация |
| AmneziaWG → WARP | Импорт WARP, нативная генерация, WARP-in-WARP |
| AmneziaWG → Routing | Selective routing: CIDR / домены / устройства / DSCP |
| sing-box | Инстансы, up/down, прозрачное проксирование (TProxy/Redirect/Hybrid) |
| mihomo | Движок Clash.Meta: установка, инстансы, YAML-редактор конфигов |
| Списки (общие) | Именованные списки доменов/CIDR для маршрутизации и nfqws2 |
| Маршрутизация | Единый слой «назначение → метод» с мониторингом и failover |

### INI-каталоги стратегий

Дополнительно доступны стратегии из INI-каталогов (из проекта [youtubediscord/zapret](https://github.com/youtubediscord/zapret) (оттуда же можно тащить обновления стратегий)):
- `catalogs/basic/` — базовые стратегии TCP/UDP
- `catalogs/advanced/` — продвинутые комбинации
- `catalogs/direct/` — прямые стратегии

Используются в **Подборе стратегий** для автоматического тестирования.

### Создание пользовательской стратегии

1. Нажмите «Создать стратегию»
2. Укажите ID, название и описание
3. Добавьте профили (каждый профиль = набор аргументов nfqws2)
4. Используйте «Превью» для проверки финальной команды
5. Сохраните и примените

## AmneziaWG integration

Раздел **AmneziaWG** в сайдбаре управляет WireGuard / AmneziaWG туннелями
поверх роутера, в том числе Cloudflare WARP, и точечной маршрутизацией
выбранного трафика в эти туннели.

### Что поддерживается

- **Бинарники `amneziawg-go` / `amneziawg-tools`** — собираются нашим
  workflow'ом под `mipsel-softfloat`, `mips-softfloat`, `aarch64`,
  `armv7`, `x86_64` и публикуются в GitHub Releases с тегом
  `awg-bin-vX`. Setup wizard скачивает подходящий архив, проверяет
  sha256 и раскладывает по `binary_dir` платформы.
- **Платформы** — Keenetic (KeenOS 4.x/5.x с Entware + OpkgTun),
  OpenWrt 22+ (procd + nftables), generic Linux (systemd +
  iptables/nftables). Init-скрипты под каждую генерируются
  автоматически.
- **Конфиги** — парсер/генератор `.conf` со всеми AmneziaWG-полями
  (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`…`H4`, `I`). В UI —
  моноширинный редактор, валидация, импорт текстом или файлом,
  экспорт `.conf`.
- **Cloudflare WARP** — три сценария:
  - **Импорт** уже сгенерированного на стороннем сайте конфига
    (эвристика по диапазонам Cloudflare WARP);
  - **Нативная генерация** через `api.cloudflareclient.com` —
    регистрация аккаунта, опционально апгрейд WARP+ по ключу,
    автоподбор AmneziaWG обфускации;
  - **WARP-in-WARP** — два WARP-туннеля поверх друг друга
    (static route для inner endpoint через outer интерфейс).
- **Selective routing** — таблица `awg<N>` → `table 100+N`,
  правила четырёх типов:
  - **CIDR** — IPv4/IPv6 сети напрямую через `ip rule from`/`ip route`;
  - **Домены** — управляемый блок `dnsmasq.d/zapret-gui-awg-routing.conf`
    с include-once в основной `dnsmasq.conf`, ipset (Entware) или
    nftables set (OpenWrt 22+);
  - **Устройства** — список из `dhcp.leases`/ARP, per-device правила
    через source-IP либо fwmark, если платформа поддерживает;
  - **DSCP** — маршрутизация по QoS-метке (`-m dscp` / `ip dscp` →
    fwmark), iptables или nftables.
- **Autostart** — per-config флаг `autostart` в `settings.json`.
  Init-скрипт под платформу вызывает `python3 app.py --apply-awg-autostart`,
  который поднимает интерфейсы и применяет routing rules в правильном
  порядке.

### С чего начать

1. **AmneziaWG → Setup** — мастер проведёт через детект окружения,
   подскажет недостающие пакеты (например, OpkgTun на Keenetic) и
   установит бинарники.
2. **AmneziaWG → WARP** — самый простой путь получить рабочий
   туннель: вкладка «Генерация» → «Сгенерировать» → «Сохранить».
3. **AmneziaWG → Dashboard** — поднять интерфейс, проверить
   handshake и трафик.
4. **AmneziaWG → Routing** — добавить правило, например
   `youtube.com,googlevideo.com → awg-warp-1`. Применяется
   автоматически при up интерфейса.

### Известные ограничения

- На Keenetic 4.x mark-based routing ограничен — per-device правила
  работают через source IP, не fwmark.
- Сборка `amneziawg-tools` под `mips-softfloat` использует Bootlin
  musl toolchain; на роутерах с очень старыми ядрами возможны
  проблемы с syscall ABI — открывайте issue с `uname -a`.

## Обновление

### Из веб-интерфейса
На странице **Zapret2** отображается уведомление о новой версии. Нажмите **Обновить GUI** и обновите страницу.

### Через пакетный менеджер
```bash
opkg upgrade zapret-gui
```

### Скриптом
```bash
./install.sh --update
```

## Сборка пакетов

```bash
# Entware / Keenetic ipk
make ipk
# → dist/zapret-gui_<version>-1_all.ipk

# OpenWrt ipk
make openwrt-ipk
# → dist/zapret-gui_<version>-1_openwrt.ipk

# Проверка синтаксиса
make lint

# Выпустить релиз (обновляет версию, создаёт тег → GitHub Actions публикует)
make release VERSION=X.Y.Z
```

## Удаление

```bash
# Через пакетный менеджер
opkg remove zapret-gui

# Скриптом (конфиг сохраняется)
./uninstall.sh

# Полное удаление
./uninstall.sh --full
```

## API

REST API: `http://<host>:8080/api/` — 120+ эндпоинтов.

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /api/status | Общий статус |
| POST | /api/start · /api/stop | Запуск/остановка nfqws2 |
| GET/POST | /api/strategies · /api/strategies/:id/apply | Стратегии |
| GET | /api/logs/stream | SSE-поток логов |
| GET/POST | /api/gui/check · /api/gui/update | Обновление GUI |
| POST | /api/blockcheck/start · /api/scan/start | BlockCheck / подбор |
| GET/POST | /api/awg/environment · /api/awg/install · /api/awg/configs/:name/{up,down} | AmneziaWG |
| POST | /api/awg/warp/{import,generate} · /api/awg/warp-in-warp | Cloudflare WARP |
| GET/POST | /api/routing/rules | Selective-routing (cidr/domain/device/**dscp**) |
| GET | /api/routing/interfaces · /api/devices | Интерфейсы / устройства |
| GET/POST | /api/singbox/configs · …/:name/{up,down,restart} | sing-box инстансы |
| GET/POST | /api/singbox/subscriptions · …/:id/refresh | Подписки + автообновление |
| GET/POST | /api/singbox/pool · …/sources · …/refresh | Пул серверов из публичных источников |
| POST/GET | /api/singbox/test · …/status | Тестер серверов (TCP + e2e через облако) |
| GET/POST | /api/singbox/transparent/{status,apply,remove} | Прозрачное проксирование |
| GET/POST | /api/mihomo/{environment,install,version,configs} | mihomo (Clash.Meta) |
| GET/POST/PUT/DELETE | /api/lists · /api/lists/:id | Именованные списки доменов/CIDR |
| GET/POST | /api/unified/routes · …/:id/{apply,scan} | Единый слой «назначение → метод» |
| GET/POST | /api/unified/status · /api/unified/monitor | Статус/мониторинг единого слоя |
| GET/POST | /api/backup/{export,summary,import} | Бэкап/восстановление конфигурации |

Полный список — см. `api/` директорию.

## CLI

После установки (ipk или `install.sh`) доступна команда `zapret-gui`
в `$PATH` — управление из консоли по SSH без браузера:

```bash
zapret-gui status                       # общий статус
zapret-gui nfqws {start|stop|restart|status}
zapret-gui strategy {list|apply <id>}
zapret-gui singbox {list|up|down|restart <name>}
zapret-gui mihomo  {list|up|down|restart <name>}
```

Обёртка вызывает `python3 <app_dir>/app.py --config <config_dir> …`,
поэтому видит то же состояние, что и веб-GUI. Из клона репозитория —
напрямую: `python3 app.py status`.

## Структура проекта

```
zapret-gui/
├── api/              # REST API (Bottle routes)
├── catalogs/         # INI-каталоги стратегий (basic/advanced/direct/builtin)
├── config/           # Стратегии (builtin JSON + user)
├── core/             # Бизнес-логика
│   ├── testers/      # Сетевые тестеры (TLS, STUN, TCP, DPI)
│   ├── connectivity/ # Матрица доступности + traffic-серии (RAM)
│   ├── routing/      # Selective routing engine (cidr/domain/device/dscp)
│   ├── ndms/         # Keenetic RCI: интерфейсы, политики хостов
│   ├── unified/      # Единый слой: model, applier, monitor, failover,
│   │                 #   geo_engine, nfqws_hostlist, scanner_hint, manager
│   ├── named_lists.py        # Общие именованные списки доменов/CIDR
│   ├── binary_installer.py   # Загрузка/распаковка + зеркало/оффлайн
│   ├── cli.py                # CLI-подкоманды (status/nfqws/strategy/…)
│   ├── awg_*.py      # AmneziaWG: platform, detector, installer, manager
│   ├── singbox_*.py  # sing-box: manager, transparent (iptables/nft), …
│   ├── mihomo_*.py   # mihomo: platform, detector, installer, manager
│   └── warp_*.py     # Cloudflare WARP: импорт, нативная генерация
├── data/             # Данные (домены, TCP-цели)
├── packaging/        # Скрипты сборки ipk (Entware/OpenWrt)
├── web/              # Фронтенд (SPA)
│   ├── css/
│   ├── js/
│   │   ├── components/   # sidebar, toast, list_ui, sparkline, help
│   │   ├── pages/        # dashboard, routing (единый слой), lists, mihomo, …
│   │   └── utils/
│   └── index.html
├── .github/workflows/
│   ├── release.yml                # CI/CD основного пакета
│   └── build-awg-binaries.yml     # Кросс-сборка amneziawg-go/-tools
├── app.py            # Точка входа
├── Makefile          # Сборка пакетов
├── install.sh        # Автоустановка
└── uninstall.sh      # Удаление
```

### Ключевые решения

- **Кроссплатформенность** — весь код на Python/JS, архитектурно-зависим только бинарник nfqws2
- **ThreadedWSGIServer** — многопоточный WSGI для параллельной обработки SSE и API
- **Логи в RAM** — `collections.deque(maxlen=2000)`, без записи на flash
- **Singleton-менеджеры** — thread-safe, lazy initialization
- **Cache-Control: no-store** — предотвращение кеширования API-ответов
- **SPA с hash-роутингом** — каждая страница — IIFE-модуль с `render()/destroy()`

## Лицензия

MIT

## Благодарности

- [bol-van/zapret2](https://github.com/bol-van/zapret) — основной инструмент
- [youtubediscord/zapret](https://github.com/youtubediscord/zapret) — вдохновлялся
- [Shiperoid/YT-DPI](https://github.com/Shiperoid/YT-DPI) — идеи диагностики
  (троттлинг, реальные CDN-шарды googlevideo, Deep Trace, QUIC, большой
  ClientHello)
- [jameszeroX/XKeen](https://github.com/jameszeroX/XKeen) — идеи
  (прозрачные режимы TProxy/Redirect/Hybrid, движок mihomo, DSCP-роутинг,
  CLI, оффлайн-зеркало, совместимость с политиками Keenetic)
- [Bottle](https://bottlepy.org/) — микро-фреймворк для Python
