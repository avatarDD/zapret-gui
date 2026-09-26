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


def list_blobs() -> list:
    """Весь реестр: имя, значение декларации, откуда оно и есть ли файл.

    Нужен всем, кто проверяет стратегию до запуска. Имя, которого в
    реестре нет, и имя, чей файл не существует, дают одинаково тихий
    результат: nfqws2 запустится, отправит ПУСТОЙ fake и обход не
    сработает — без ошибки при старте и без строки в журнале.

    Returns:
        list[dict]: ``name``, ``value`` (часть после ``NAME:``),
        ``kind`` (``file``/``inline``/``builtin``), ``path`` (для
        файловых), ``exists``, ``builtin``. Отсортирован по имени.
    """
    _ensure_loaded()
    with _lock:
        pairs = sorted(_registry.items())

    out = []
    for name in sorted(BUILTIN_BLOB_NAMES):
        # Встроенные в nfqws2 имена в реестре не лежат (и не должны:
        # декларировать их не надо), но модели они нужны — иначе она
        # сочтёт fake_default_tls неизвестным и полезет его объявлять.
        out.append({
            "name": name,
            "value": "",
            "kind": "builtin",
            "path": "",
            "exists": True,
            "builtin": True,
        })

    for name, value in pairs:
        item = {
            "name": name,
            "value": value,
            "kind": "inline" if str(value).startswith("0x") else "file",
            "path": "",
            "exists": True,
            "builtin": False,
        }
        if item["kind"] == "file":
            item["path"] = _blob_file_path(value)
            item["exists"] = bool(item["path"]
                                  and os.path.exists(item["path"]))
        out.append(item)

    # Пользовательские блобы со страницы «Блобы» — тоже объявляемые имена.
    known = {x["name"] for x in out}
    try:
        from core.blob_manager import get_blob_manager
        user = [b for b in get_blob_manager().get_blobs()
                if not b.get("is_builtin")]
    except Exception:                   # noqa: BLE001 — граница
        user = []
    for b in user:
        name = b.get("name") or ""
        if name in known or not _user_blob_path(name):
            continue
        out.append({
            "name": name,
            "value": "@" + b.get("path", ""),
            "kind": "user",
            "path": b.get("path", ""),
            "exists": True,
            "builtin": False,
        })
    return out


def _blob_file_path(value: str) -> str:
    """Путь к файлу из значения декларации ``@bin/file.bin``.

    Относительные пути резолвятся тем же ``bin_path``, что и при сборке
    argv (``CatalogManager.resolve_paths_in_args``), иначе «файла нет»
    здесь означало бы «файла нет по другому пути», а это хуже, чем
    молчание.
    """
    value = str(value or "").strip()
    if not value.startswith("@"):
        return ""
    path = value[1:]
    if os.path.isabs(path):
        return path
    if path.startswith("bin/"):
        path = path[4:]
    try:
        from core.config_manager import get_config_manager
        zapret = (get_config_manager().effective().get("zapret") or {})
        base = zapret.get("bin_path") or "/opt/zapret2/files/fake"
    except Exception:                   # noqa: BLE001 — граница
        base = "/opt/zapret2/files/fake"
    return os.path.join(base, path)


def _user_blob_path(name: str) -> str:
    """Файл пользовательского блоба (страница «Блобы», MCP blob_add).

    Такие блобы лежат в {base_path}/blobs/<имя> и в реестр из каталогов
    не попадают. Раньше это значило, что созданный в GUI блоб по ссылке
    blob=<имя> nfqws2 не получал вовсе: декларацию собрать было не из
    чего, и fake уходил пустым. Теперь имя ищется и там. Только имена,
    годные nfqws2 в `--blob=<имя>:`, и не встроенные.
    """
    if not name or name in BUILTIN_BLOB_NAMES \
            or not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", name):
        return ""
    try:
        from core.config_manager import get_config_manager
        base = get_config_manager().get("zapret", "base_path",
                                        default="/opt/zapret2")
    except Exception:                   # noqa: BLE001 — граница
        base = "/opt/zapret2"
    path = os.path.join(base or "/opt/zapret2", "blobs", name)
    return path if os.path.isfile(path) else ""


def get_blob_value(name: str):
    """Значение декларации для имени blob'а или None, если не известно.

    Каталожные имена важнее пользовательских: tls_google всегда тот,
    что в пресетах, даже если рядом лежит свой файл с таким именем.
    """
    _ensure_loaded()
    value = _registry.get(name)
    if value is not None:
        return value
    path = _user_blob_path(name)
    return ("@" + path) if path else None


def aliases_for_file(path: str) -> list:
    """Имена реестра, под которыми подставляют этот файл (tls_google …)."""
    _ensure_loaded()
    base = os.path.basename(str(path or ""))
    if not base:
        return []
    with _lock:
        pairs = sorted(_registry.items())
    return [name for name, value in pairs
            if str(value).startswith("@")
            and os.path.basename(str(value)[1:]) == base]


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
        value = get_blob_value(name)
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
