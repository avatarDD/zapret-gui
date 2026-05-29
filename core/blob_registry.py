# core/blob_registry.py
"""
Реестр именованных blob'ов для nfqws2.

Контекст проблемы
─────────────────
В nfqws2 fake-пакеты задаются ссылкой на ИМЕНОВАННЫЙ blob:

    --lua-desync=fake:blob=tls_google:...

Само имя ``tls_google`` ничего не значит, пока оно не зарегистрировано
глобально через декларацию:

    --blob=tls_google:@/opt/zapret2/files/fake/tls_clienthello_www_google_com.bin

Полные пресеты (catalogs/builtin/winws2_presets.txt) встраивают такие
``--blob=...`` декларации прямо в первый профиль и работают. А компактные
каталоги (basic/advanced) указывают только метаполе ``blobs = tls_google``
и голую ссылку ``blob=tls_google`` — без декларации. Метаполе при сборке
аргументов раньше отбрасывалось, поэтому nfqws2 отправлял ПУСТОЙ fake и
обход не срабатывал.

Этот модуль — единый источник маппинга «символическое имя → файл blob'а».
Он:
  • извлекает каноничные ``--blob=NAME:@bin/FILE.bin`` декларации из каталогов
    (catalogs/builtin/winws2_presets.txt — там полный список из upstream);
  • дополняет их встроенной таблицей (fallback, если каталог недоступен);
  • по списку аргументов стратегии генерирует недостающие ``--blob=``
    декларации, которые нужно подмешать ОДИН раз в начало (до первого
    ``--new``), т.к. blob-декларации в nfqws2 глобальны.

Встроенные имена nfqws2 (fake_default_http/tls/quic) и инлайновые hex-blob'ы
(``blob=0x00...``) регистрации НЕ требуют и пропускаются.
"""

import os
import re
import threading

from core.log_buffer import log


# Имя → значение декларации (часть после "NAME:" в --blob=NAME:VALUE).
# Значение может быть "@bin/file.bin" (файл) или "0x..." (инлайн-hex).
# Заполняется лениво из каталогов + _FALLBACK_ALIASES.
_registry: dict = {}
_loaded = False
_lock = threading.Lock()


# Имена, встроенные в сам nfqws2 — регистрировать не нужно.
BUILTIN_BLOB_NAMES = frozenset({
    "fake_default_http",
    "fake_default_tls",
    "fake_default_quic",
})

# Каноничный fallback-маппинг (синхронизирован с заголовком
# catalogs/builtin/winws2_presets.txt). Используется, если каталог
# почему-то недоступен при импорте/запуске.
_FALLBACK_ALIASES = {
    "tls_google":   "@bin/tls_clienthello_www_google_com.bin",
    "tls1":         "@bin/tls_clienthello_1.bin",
    "tls2":         "@bin/tls_clienthello_2.bin",
    "tls2n":        "@bin/tls_clienthello_2n.bin",
    "tls3":         "@bin/tls_clienthello_3.bin",
    "tls4":         "@bin/tls_clienthello_4.bin",
    "tls5":         "@bin/tls_clienthello_5.bin",
    "tls6":         "@bin/tls_clienthello_6.bin",
    "tls7":         "@bin/tls_clienthello_7.bin",
    "tls8":         "@bin/tls_clienthello_8.bin",
    "tls9":         "@bin/tls_clienthello_9.bin",
    "tls10":        "@bin/tls_clienthello_10.bin",
    "tls11":        "@bin/tls_clienthello_11.bin",
    "tls12":        "@bin/tls_clienthello_12.bin",
    "tls13":        "@bin/tls_clienthello_13.bin",
    "tls14":        "@bin/tls_clienthello_14.bin",
    "tls17":        "@bin/tls_clienthello_17.bin",
    "tls18":        "@bin/tls_clienthello_18.bin",
    "tls_sber":     "@bin/tls_clienthello_sberbank_ru.bin",
    "tls_vk":       "@bin/tls_clienthello_vk_com.bin",
    "tls_vk_kyber": "@bin/tls_clienthello_vk_com_kyber.bin",
    "tls_deepseek": "@bin/tls_clienthello_chat_deepseek_com.bin",
    "tls_max":      "@bin/tls_clienthello_max_ru.bin",
    "tls_iana":     "@bin/tls_clienthello_iana_org.bin",
    "tls_4pda":     "@bin/tls_clienthello_4pda_to.bin",
    "tls_gosuslugi": "@bin/tls_clienthello_gosuslugi_ru.bin",
    "syndata3":     "@bin/tls_clienthello_3.bin",
    "syn_packet":   "@bin/syn_packet.bin",
    "dtls_w3":      "@bin/dtls_clienthello_w3_org.bin",
    "quic_google":  "@bin/quic_initial_www_google_com.bin",
    "quic_vk":      "@bin/quic_initial_vk_com.bin",
    "quic1":        "@bin/quic_1.bin",
    "quic2":        "@bin/quic_2.bin",
    "quic3":        "@bin/quic_3.bin",
    "quic4":        "@bin/quic_4.bin",
    "quic5":        "@bin/quic_5.bin",
    "quic6":        "@bin/quic_6.bin",
    "quic7":        "@bin/quic_7.bin",
    "stun_pat":     "@bin/stun.bin",
    "quic_test":    "@bin/quic_test_00.bin",
    "fake_tls":     "@bin/fake_tls_1.bin",
    "fake_tls_1":   "@bin/fake_tls_1.bin",
    "fake_tls_2":   "@bin/fake_tls_2.bin",
    "fake_tls_3":   "@bin/fake_tls_3.bin",
    "fake_tls_4":   "@bin/fake_tls_4.bin",
    "fake_tls_5":   "@bin/fake_tls_5.bin",
    "fake_tls_6":   "@bin/fake_tls_6.bin",
    "fake_tls_7":   "@bin/fake_tls_7.bin",
    "fake_tls_8":   "@bin/fake_tls_8.bin",
    "fake_quic":    "@bin/fake_quic.bin",
    "fake_quic_1":  "@bin/fake_quic_1.bin",
    "fake_quic_2":  "@bin/fake_quic_2.bin",
    "fake_quic_3":  "@bin/fake_quic_3.bin",
    "fake_default_udp": "0x00000000000000000000000000000000",
    "http_req":     "@bin/http_iana_org.bin",
    "hex_0e0e0f0e": "0x0E0E0F0E",
    "hex_0f0e0e0f": "0x0F0E0E0F",
    "hex_0f0f0f0f": "0x0F0F0F0F",
    "hex_00":       "0x00",
}


# --blob=NAME:VALUE из каталогов (для пополнения реестра из upstream).
_BLOB_DECL_RE = re.compile(r"^--blob=([^:]+):(.+)$")

# blob=NAME внутри --lua-desync=...:blob=NAME:... (имя — до ':' или конца).
_BLOB_REF_RE = re.compile(r"blob=([A-Za-z0-9_]+)")


def _catalogs_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "catalogs",
    )


def _load_from_catalogs(registry: dict) -> int:
    """Пополнить registry декларациями ``--blob=NAME:VALUE`` из каталогов.

    Каталоги — источник истины (winws2_presets.txt содержит полный
    upstream-список). Возвращает число добавленных/обновлённых имён.
    """
    root = _catalogs_dir()
    count = 0
    if not os.path.isdir(root):
        return 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".txt"):
                continue
            try:
                with open(os.path.join(dirpath, fn), "r",
                          encoding="utf-8", errors="replace") as f:
                    for raw in f:
                        line = raw.strip()
                        if not line.startswith("--blob="):
                            continue
                        m = _BLOB_DECL_RE.match(line)
                        if not m:
                            continue
                        name, value = m.group(1).strip(), m.group(2).strip()
                        if name and value:
                            registry[name] = value
                            count += 1
            except (IOError, OSError):
                continue
    return count


def _ensure_loaded():
    global _loaded
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        reg = dict(_FALLBACK_ALIASES)
        try:
            n = _load_from_catalogs(reg)
            if n:
                log.debug("blob-реестр: %d деклараций из каталогов, %d всего"
                          % (n, len(reg)), source="blobs")
        except Exception as e:  # noqa: BLE001 — реестр не должен ронять запуск
            log.warning("blob-реестр: ошибка чтения каталогов: %s" % e,
                        source="blobs")
        _registry.clear()
        _registry.update(reg)
        _loaded = True


def reload_registry():
    """Сбросить кэш реестра (например, после обновления каталогов)."""
    global _loaded
    with _lock:
        _loaded = False
        _registry.clear()


def get_blob_value(name: str):
    """Значение декларации для имени blob'а или None, если не известно."""
    _ensure_loaded()
    return _registry.get(name)


def referenced_blob_names(args) -> list:
    """Имена blob'ов, на которые ссылаются аргументы стратегии.

    Ищет ``blob=NAME`` в любом аргументе (как правило, внутри
    ``--lua-desync=fake:blob=NAME:...``). Возвращает уникальные имена
    в порядке первого появления.
    """
    seen = []
    seen_set = set()
    for a in args:
        for m in _BLOB_REF_RE.finditer(a):
            name = m.group(1)
            if name not in seen_set:
                seen_set.add(name)
                seen.append(name)
    return seen


def already_declared(args) -> set:
    """Имена blob'ов, уже объявленные через ``--blob=NAME:...`` в аргументах."""
    declared = set()
    for a in args:
        if a.startswith("--blob="):
            m = _BLOB_DECL_RE.match(a)
            if m:
                declared.add(m.group(1).strip())
    return declared


def build_blob_declarations(args) -> list:
    """Сгенерировать недостающие ``--blob=NAME:VALUE`` для аргументов стратегии.

    Логика:
      • собираем имена из ссылок ``blob=NAME``;
      • выкидываем встроенные (fake_default_*) и инлайн-hex (``0x...``);
      • выкидываем уже объявленные в самих аргументах;
      • для остальных, если имя есть в реестре, формируем декларацию.

    Возвращает список строк ``--blob=NAME:VALUE`` (значения с ``@bin/`` будут
    отрезолвлены в абсолютный путь позже, в CatalogManager.resolve_paths_in_args).
    Декларации глобальны — их следует подмешать ОДИН раз в начало команды,
    до первого ``--new``.
    """
    _ensure_loaded()
    declared = already_declared(args)
    out = []
    for name in referenced_blob_names(args):
        if name in BUILTIN_BLOB_NAMES:
            continue
        if name.startswith("0x"):  # инлайновый hex, не имя
            continue
        if name in declared:
            continue
        value = _registry.get(name)
        if value is None:
            # Неизвестное имя — не молчим, но и не падаем: nfqws2 сам
            # сообщит об отсутствующем blob'е. Чаще всего это опечатка
            # в пользовательской стратегии.
            log.warning("blob '%s' не найден в реестре — fake может быть пуст"
                        % name, source="blobs")
            continue
        out.append("--blob=%s:%s" % (name, value))
        declared.add(name)
    return out
