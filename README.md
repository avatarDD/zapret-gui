# Zapret Web-GUI

Web-интерфейс для управления **nfqws2** (zapret2) на роутерах с **Entware** (Keenetic) и **OpenWrt**.

![Version](https://img.shields.io/badge/version-0.11.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## Возможности

- **Управление nfqws2** — запуск, остановка, перезапуск с мониторингом статуса
- **Стратегии desync** — встроенные и пользовательские, с подсветкой синтаксиса
- **Списки доменов** — hostlists с нормализацией, импортом из URL, дефолтными списками
- **IP-списки** — ipsets с поддержкой ASN-загрузки (stat.ripe.net)
- **Блобы** — hex-редактор, генерация fake TLS/HTTP ClientHello
- **Hosts-файл** — управление /etc/hosts, пресеты, бэкапы
- **Диагностика** — ping, HTTP/DNS проверки, конфликты, системная информация
- **Логи в реальном времени** — SSE, фильтрация по уровню, поиск, автопрокрутка
- **Автозапуск** — генерация init-скрипта S99zapret
- **Firewall** — автоопределение iptables/nftables, управление NFQUEUE правилами
- **Zapret Manager** — установка/обновление/удаление zapret2 с GitHub
- **Адаптивный дизайн** — тёмная тема, мобильный интерфейс

## Требования

### Entware (Keenetic и другие)
```
opkg install python3-light python3-bottle
```

### OpenWrt
```
opkg install python3-light python3-bottle
```

### Минимальные требования
- RAM: ~20–25 MB
- Flash: ~500 KB (+ python3-light ~5 MB)
- Python 3.7+

## Установка

### Вариант 1: ipk-пакет (рекомендуется)

**Entware:**
```bash
# Скачать последний релиз
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui_0.11.0_all.ipk

# Установить
opkg install zapret-gui_0.11.0_all.ipk

# Запустить
/opt/etc/init.d/S99zapret-gui start
```

**OpenWrt:**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui_0.11.0_openwrt_all.ipk
opkg install zapret-gui_0.11.0_openwrt_all.ipk
/etc/init.d/zapret-gui start
```

### Вариант 2: Автоустановка скриптом

```bash
wget -O - https://raw.githubusercontent.com/avatarDD/zapret-gui/master/install.sh | sh
```

Скрипт автоматически:
- Определит платформу (Entware/OpenWrt)
- Установит зависимости (python3-light, python3-bottle)
- Скачает и распакует проект
- Создаст init-скрипт
- Запустит Web-GUI

### Вариант 3: Ручная установка

```bash
# Клонировать
cd /opt
git clone https://github.com/avatarDD/zapret-gui.git
cd zapret-gui

# Установить зависимости
opkg install python3-light python3-bottle

# Запустить
python3 app.py --host 0.0.0.0 --port 8080
```

## Использование

После установки Web-GUI доступен по адресу:
```
http://<IP-роутера>:8080
```

### Быстрый старт

1. Перейдите в раздел **Zapret2** → установите nfqws2
2. Перейдите в **Стратегии** → выберите и примените подходящую стратегию
3. Включите **Автозапуск** для работы после перезагрузки
4. Проверьте в **Диагностике** доступность сервисов

### Страницы

| Страница | Описание |
|----------|----------|
| Главная | Статус nfqws, текущая стратегия, быстрые действия |
| Управление | Старт/стоп/рестарт, мониторинг процесса |
| Стратегии | Список стратегий, применение, редактор, превью команды |
| Домены | Списки хостов для фильтрации (hostlists) |
| IP-списки | IP-адреса и подсети, загрузка по ASN |
| Блобы | Бинарные данные для fake-пакетов |
| Hosts | Управление /etc/hosts |
| Zapret2 | Установка/обновление/удаление nfqws2 |
| Диагностика | Проверка сервисов, конфликтов, системы |
| Логи | Журнал событий в реальном времени |
| Автозапуск | Управление init-скриптом |
| Настройки | Конфигурация GUI, nfqws, firewall |

## Конфигурация

Конфигурация хранится в `/opt/etc/zapret-gui/settings.json`.

### Основные параметры

```json
{
  "gui": {
    "host": "0.0.0.0",
    "port": 8080,
    "auth_enabled": false,
    "auth_user": "admin",
    "auth_password": ""
  },
  "nfqws": {
    "queue_num": 300,
    "ports_tcp": "80,443",
    "ports_udp": "443"
  }
}
```

### Безопасность

По умолчанию GUI доступен на всех интерфейсах (0.0.0.0:8080).
Для ограничения доступа:

- **Привязка к localhost:** `"host": "127.0.0.1"` (доступ только через SSH-туннель)
- **Авторизация:** Включите в настройках Basic Auth
- **Firewall:** Ограничьте доступ правилами iptables

## Стратегии

### Встроенные стратегии

| ID | Описание |
|----|----------|
| tcp_default | Базовая: fake + multisplit для HTTP/TLS, fake для QUIC |
| tcp_alt1 | fake с TCP MD5 опцией |
| tcp_alt2 | multidisorder + tcp_seq offset |
| tcp_hostfake | Подмена SNI в fake-пакетах |
| tcp_oob | fakedsplit + disorder + TTL fooling |
| tcp_syndata | SYN data + fake |
| quic_only | Только QUIC/UDP |
| full_combo | Все протоколы с агрессивными параметрами |

### Создание пользовательской стратегии

1. Нажмите «Создать стратегию»
2. Укажите ID, название и описание
3. Добавьте профили (каждый профиль = набор аргументов nfqws2)
4. Используйте «Превью» для проверки финальной команды
5. Сохраните и примените

### Синтаксис аргументов (nfqws2)

```
--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=3
--lua-desync=multisplit:pos=1,midsld
```

### Синтаксис аргументов (classic nfqws)

```
--filter-tcp=443 --dpi-desync=fake,multisplit
--dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq
--dpi-desync-fake-tls=tls_clienthello.bin --new
```

## Сборка пакетов

### Entware ipk

```bash
make clean
make ipk
# Результат: build/zapret-gui_0.11.0_all.ipk
```

### OpenWrt ipk

```bash
make openwrt-ipk
# Результат: build/zapret-gui_0.11.0_openwrt_all.ipk
```

## Удаление

### Через пакетный менеджер
```bash
opkg remove zapret-gui
```

### Скриптом
```bash
./uninstall.sh           # с сохранением конфига
./uninstall.sh --purge   # полное удаление
```

## API

REST API доступно по адресу `http://<host>:8080/api/`.

### Основные эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /api/status | Общий статус |
| POST | /api/start | Запустить nfqws2 |
| POST | /api/stop | Остановить nfqws2 |
| GET | /api/strategies | Список стратегий |
| POST | /api/strategies/:id/apply | Применить стратегию |
| GET | /api/logs | Последние записи логов |
| GET | /api/logs/stream | SSE-поток логов (real-time) |

Полный список — 76 эндпоинтов (см. `api/` директорию).

## Архитектура

```
zapret-gui/
├── app.py                 — Bottle сервер (ThreadedWSGI)
├── api/                   — REST API модули (13 файлов)
├── core/                  — Бизнес-логика (14 файлов)
├── web/
│   ├── index.html         — SPA точка входа
│   ├── css/style.css      — Тёмная тема (~3500 строк)
│   └── js/
│       ├── api.js         — HTTP-клиент
│       ├── app.js         — Hash-роутер
│       ├── utils/         — Утилиты (syntax, debounce)
│       ├── components/    — Sidebar, Toast
│       └── pages/         — 12 страниц (IIFE модули)
├── config/                — Стратегии и категории
├── packaging/             — ipk-пакеты (Entware/OpenWrt)
├── install.sh             — Автоустановка
└── uninstall.sh           — Удаление
```

### Ключевые решения

- **ThreadedWSGIServer** — многопоточный WSGI для параллельной обработки SSE и API
- **Логи в RAM** — `collections.deque(maxlen=2000)`, без записи на flash
- **Singleton-менеджеры** — thread-safe, lazy initialization
- **Cache-Control: no-store** — предотвращение кеширования API-ответов
- **SPA с hash-роутингом** — каждая страница — IIFE-модуль с `render()/destroy()`

## FAQ

**Q: Сколько RAM потребляет GUI?**
A: ~20–25 MB (Python3 + Bottle). Для роутеров с 128+ MB RAM это приемлемо.

**Q: Не теряются ли логи при перезагрузке?**
A: Да, логи хранятся в RAM (/tmp/). Это нормально для роутера — flash не изнашивается.

**Q: Как обновить GUI?**
A: `opkg install zapret-gui_NEW.ipk` или через раздел «Zapret2» в GUI.

**Q: Можно ли использовать одновременно с существующим zapret2?**
A: GUI является надстройкой и использует те же файлы zapret2. Не запускайте nfqws2 одновременно из GUI и из скрипта.

**Q: Поддерживается ли IPv6?**
A: Да. Можно отключить в настройках (`nfqws.disable_ipv6`).

## Лицензия

MIT License. См. файл LICENSE.

## Благодарности

- [zapret2/nfqws2](https://github.com/bol-van/zapret) — основной инструмент
- [Bottle](https://bottlepy.org/) — микро-фреймворк для Python
