# core/bottle_vendor.py
"""
Подключение встроенного bottle из vendor/ (фолбэк).

Bottle поставляется вместе с проектом (vendor/bottle.py), чтобы
установка не требовала сети (opkg/PyPI/GitHub у целевой аудитории
часто заблокированы), а dev-окружение и api-тесты работали без
`pip install bottle`.

Приоритет — у системного модуля: если `import bottle` работает
(например, стоит opkg-пакет python3-bottle), vendor/ не трогаем —
поведение существующих установок не меняется. Путь к vendor/
добавляется в sys.path только когда системного bottle нет.

Использование (до первого `from bottle import ...`):

    from core.bottle_vendor import ensure_bottle
    ensure_bottle()

Этот модуль сам bottle на уровне модуля не импортирует — core/ обязан
оставаться импортируемым без веб-зависимостей (см. core/selfcheck.py).
"""

import os
import sys

# vendor/ лежит в корне проекта, рядом с core/
VENDOR_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")


def vendored_bottle_path() -> str:
    """Путь к встроенному bottle.py (существование не проверяется)."""
    return os.path.join(VENDOR_DIR, "bottle.py")


def ensure_bottle():
    """Гарантировать импортируемость bottle; вернуть модуль.

    Сначала пробуем системный. Если его нет — добавляем vendor/ в
    sys.path (в начало: если системная установка битая и падает на
    импорте, повторная попытка должна найти vendored-файл раньше неё)
    и импортируем встроенный. ImportError пробрасывается, только если
    нет ни системного bottle, ни vendor/bottle.py (неполная копия
    проекта).
    """
    try:
        import bottle
        return bottle
    except ImportError:
        pass

    if os.path.isfile(vendored_bottle_path()) and VENDOR_DIR not in sys.path:
        sys.path.insert(0, VENDOR_DIR)

    import bottle
    return bottle


def is_vendored(bottle_module) -> bool:
    """True, если переданный модуль bottle загружен из vendor/."""
    path = getattr(bottle_module, "__file__", "") or ""
    try:
        return os.path.dirname(os.path.abspath(path)) == VENDOR_DIR
    except Exception:
        return False
