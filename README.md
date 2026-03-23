# zapret-gui
zapret2 web-gui for Keenetic, OpenWRT

Для запуска на роутерах Keenetic надо доустановить необходимое:
`opkg install python3-pip`
`pip3 install bottle && python3`

Склонировать данный реп, перейти в него и запустить:
`python3 app.py --port 8080`

В браузере открыть: `http://<ip_роутера>:8080/`

При этом zapret2 должен уже стоять в `/opt/zapret2/`


<img width="1467" height="1186" alt="изображение" src="https://github.com/user-attachments/assets/876ee6ec-46f7-4034-9a98-b9a91b76fe16" />

### Стек: Python3 (Bottle) + lighttpd

| Компонент | Реализация |
|-----------|-----------|
| Backend | Python3 + Bottle (micro-framework, 1 файл, 100KB) |
| Web-сервер | Встроенный в Bottle (dev) или lighttpd reverse proxy (prod) |
| Frontend | Vanilla HTML/CSS/JS + Alpine.js (3KB) для реактивности |
| Конфигурация | JSON-файлы |
| Логи | Кольцевой буфер в /tmp/ (collections.deque) |
| Пакетирование | ipk с зависимостью python3-light |

**Плюсы:**
- Удобная разработка — идеально для AI-ассистента (один промпт = один модуль; python = 90% безошибочного кода при вайбкодинге в сравнении с др. ЯП )
- Нативная работа с JSON, файлами, процессами
- Bottle — микрофреймворк в одном файле, 0 зависимостей кроме Python
- WebSocket (через gevent или polling) для real-time логов
- python3-light есть в Entware (~5MB)
- Хорошая обработка ошибок, отладка
- Легко вызывать shell-скрипты zapret2 через subprocess

**Минусы:**
- Python3 потребляет ~15-25 MB RAM (с Bottle ~20MB)
- Время холодного старта ~2-3 секунды на mipsel
- Нужна зависимость python3-light в Entware

**Оценка RAM:** 18-25 MB | **Оценка размера пакета:** ~500KB (+ python3-light ~5MB)

## Технические решения

### Хранение логов без убийства flash
- **В RAM:** `/tmp/zapret-gui.log` — кольцевой буфер (deque), макс. 2000 строк / 500KB
- **При перезагрузке:** логи теряются (это нормально для роутера)
- **Персистентные ошибки:** только CRITICAL пишутся в `/opt/etc/zapret-gui/errors.log` (макс. 50KB)

### Firewall
- Автоопределение: iptables (Keenetic) или nftables (OpenWrt 22+)
- Правила из zapret2 `common/ipt.sh` / `common/nft.sh` — адаптированы в Python

### Безопасность Web-GUI
- Привязка к 127.0.0.1 по умолчанию (доступ только с роутера или через SSH tunnel)
- Опционально: basic auth (логин/пароль в конфиге)
- Опционально: привязка к LAN-интерфейсу (доступ из локальной сети)

### Совместимость с zapret2
- Web-GUI НЕ заменяет zapret2, а является надстройкой
- Использует те же файлы списков (`/opt/zapret2/lists/`)
- Вызывает `nfqws2` напрямую или через существующие init-скрипты
- Конфигурация GUI хранится отдельно в `/opt/etc/zapret-gui/`
