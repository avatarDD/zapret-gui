# vendor/ — встроенные сторонние библиотеки

Однофайловые зависимости, которые поставляются вместе с zapret-gui,
чтобы установка **не требовала сети** (opkg/PyPI/GitHub у целевой
аудитории часто заблокированы) и чтобы dev-окружение и тесты работали
без `pip install`.

Подключение — фолбэк: если модуль есть в системе (например, opkg-пакет
`python3-bottle`), используется системный; vendor/ добавляется в
`sys.path` только когда системного нет. См. `core/bottle_vendor.py`.

## bottle.py

| Что       | Значение |
|-----------|----------|
| Версия    | 0.13.4 (пин) |
| Источник  | PyPI, wheel `bottle-0.13.4-py2.py3-none-any.whl` |
| sha256    | `e7e27201eda83d31324484235b1f17b77b26c1d1c015023101fdd84f5fd70176` |
| Лицензия  | MIT — см. `bottle.LICENSE` (Copyright (c) 2009-2024, Marcel Hellkamp) |

Файл не модифицирован — байт-в-байт из wheel.

### Как обновить

```sh
pip3 download bottle==<версия> --no-deps -d /tmp/bottle_dl
python3 -m zipfile -e /tmp/bottle_dl/bottle-<версия>-*.whl /tmp/bottle_dl/x
cp /tmp/bottle_dl/x/bottle.py vendor/bottle.py
cp /tmp/bottle_dl/x/bottle-*.dist-info/licenses/LICENSE vendor/bottle.LICENSE
sha256sum vendor/bottle.py   # обновить таблицу выше
python3 -m unittest tests.test_api_lists   # smoke на vendored-версии
```

После обновления прогнать api-тесты и поднять GUI локально: bottle
меняет поведение между 0.12/0.13 (multipart, ConfigDict) — наш код
обязан работать и с системными 0.12.x с роутеров, и с vendored-версией.
