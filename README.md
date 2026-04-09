# Zapret Web-GUI

[![Release](https://img.shields.io/github/v/release/avatarDD/zapret-gui?style=flat-square)](https://github.com/avatarDD/zapret-gui/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/avatarDD/zapret-gui/release.yml?style=flat-square&label=build)](https://github.com/avatarDD/zapret-gui/actions)
[![License](https://img.shields.io/github/license/avatarDD/zapret-gui?style=flat-square)](LICENSE)

Веб-интерфейс для управления **nfqws2** (zapret2) на роутерах с Entware (Keenetic) и OpenWrt.

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

## Требования

- Python 3.11+ (`python3-light` в Entware)
- Bottle (`python3-bottle` или `pip3 install bottle`)
- RAM: ~20–25 MB, Flash: ~500 KB (+ python3-light ~5 MB)
- Архитектура: любая (mipsel, arm64, armv7, x86_64, mips, riscv64)

## Установка

### Вариант 1: ipk-пакет (рекомендуется)

**Entware:**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui_0.14.0-1_all.ipk
opkg install zapret-gui_0.14.0-1_all.ipk
/opt/etc/init.d/S99zapret-gui start
```

**OpenWrt:**
```bash
wget https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui_0.14.0-1_openwrt.ipk
opkg install zapret-gui_0.14.0-1_openwrt.ipk
/etc/init.d/zapret-gui start
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

## Использование

Веб-интерфейс: `http://<IP-роутера>:8080`

### Быстрый старт

1. **Zapret2** → установите nfqws2
2. **Стратегии** → выберите и примените стратегию
3. Или **Подбор стратегий** → автоматический поиск рабочей стратегии
4. **Автозапуск** → включите для работы после перезагрузки
5. **BlockCheck** или **Диагностика** → проверьте доступность

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
| Настройки | Конфигурация GUI, nfqws, firewall |

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
# Entware ipk
make ipk
# → dist/zapret-gui_0.14.0-1_all.ipk

# OpenWrt ipk
make openwrt-ipk
# → dist/zapret-gui_0.14.0-1_openwrt.ipk

# Проверка синтаксиса
make lint
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

REST API: `http://<host>:8080/api/` — 80+ эндпоинтов.

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /api/status | Общий статус |
| POST | /api/start | Запустить nfqws2 |
| POST | /api/stop | Остановить nfqws2 |
| GET | /api/strategies | Список стратегий |
| POST | /api/strategies/:id/apply | Применить стратегию |
| GET | /api/logs/stream | SSE-поток логов |
| GET | /api/gui/check | Проверить обновления |
| POST | /api/gui/update | Обновить GUI |
| POST | /api/blockcheck/start | Запустить BlockCheck |
| POST | /api/scan/start | Запустить подбор стратегий |

Полный список — см. `api/` директорию.

## Структура проекта

```
zapret-gui/
├── api/              # REST API (Bottle routes)
├── catalogs/         # INI-каталоги стратегий (basic/advanced/direct/builtin)
├── config/           # Стратегии (builtin JSON + user)
├── core/             # Бизнес-логика
│   └── testers/      # Сетевые тестеры (TLS, STUN, TCP, DPI)
├── data/             # Данные (домены, TCP-цели)
├── packaging/        # Скрипты сборки ipk (Entware/OpenWrt)
├── web/              # Фронтенд (SPA)
│   ├── css/
│   ├── js/
│   │   ├── components/
│   │   ├── pages/
│   │   └── utils/
│   └── index.html
├── .github/workflows/release.yml  # CI/CD
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
- [Bottle](https://bottlepy.org/) — микро-фреймворк для Python
