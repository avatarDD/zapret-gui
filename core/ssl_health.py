# core/ssl_health.py
"""
Есть ли у Python HTTPS.

Все запросы к GitHub (последние версии, манифесты, установка) идут через
urllib, а HTTPS в urllib есть только при загружаемом модуле ``ssl``. На
роутерах он бывает сломан: на Keenetic встречалось

    libssl.so.3: cannot open shared object file: Structure needs cleaning

«Structure needs cleaning» (EUCLEAN) — это не сеть и не GitHub: файловая
система накопителя Entware повреждена, и библиотеку OpenSSL нельзя
прочитать. Пока ``ssl`` не грузится, urllib для https отвечает «unknown
url type: https», а модули, импортирующие ``ssl``, падают с текстом выше.
Обойти это внутри Python нельзя (TLS без OpenSSL нет), а curl и wget-ssl
тянут ту же libssl. Поэтому модуль не пытается «скачать иначе», а
называет причину и что с ней делать — одной фразой вместо девяти строк
«источник не ответил».
"""

import errno

_cached = None

# В errno Windows/macOS EUCLEAN нет; 117 — его номер в Linux.
_EUCLEAN = getattr(errno, "EUCLEAN", 117)


def _diagnose(exc) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    low = text.lower()
    if "structure needs cleaning" in low or \
            getattr(exc, "errno", None) == _EUCLEAN:
        lib = "libssl" if "libssl" in low else (
            "libcrypto" if "libcrypto" in low else "OpenSSL")
        return ("Python не может загрузить SSL (%s): файл библиотеки %s"
                " повреждён — ошибка файловой системы накопителя"
                " («Structure needs cleaning»). Без SSL до GitHub не"
                " достучаться ни по какому адресу https. Что сделать:"
                " проверить накопитель на ошибки (e2fsck на ПК или"
                " проверкой диска в веб-интерфейсе роутера), затем"
                " переустановить библиотеку:"
                " opkg install --force-reinstall libopenssl" % (text, lib))
    if "libssl" in low or "libcrypto" in low:
        return ("Python не может загрузить SSL (%s): нет библиотеки"
                " OpenSSL. Без SSL до GitHub не достучаться. Что сделать:"
                " opkg install --force-reinstall libopenssl" % text)
    return ("В Python нет модуля SSL (%s), поэтому адреса https недоступны."
            " Что сделать: установить модуль, на Entware —"
            " opkg install python3-openssl" % text)


def ssl_problem(refresh: bool = False) -> str:
    """'' — SSL в порядке; иначе понятное описание поломки и что делать.

    Результат кешируется: импорт ``ssl`` в процессе либо удался, либо нет,
    и повторная попытка в том же процессе ничего не изменит (refresh —
    для тестов).
    """
    global _cached
    if _cached is not None and not refresh:
        return _cached
    try:
        import ssl  # noqa: F401
        _cached = ""
    except Exception as e:      # ImportError / OSError из загрузчика
        _cached = _diagnose(e)
    return _cached


def looks_like_ssl_error(text) -> bool:
    """Похож ли текст ошибки на последствие сломанного SSL в Python."""
    low = str(text or "").lower()
    return ("unknown url type: https" in low or "libssl" in low
            or "libcrypto" in low or "no module named '_ssl'" in low
            or "no module named 'ssl'" in low
            or "structure needs cleaning" in low)
