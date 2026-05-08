# core/lua_manager.py
"""
Менеджер Lua-скриптов для nfqws2 (--lua-init=@lua/*.lua).

Управляет файлами в директории lua_path (обычно /opt/zapret2/lua):
  - bundled-скрипты (zapret-lib.lua, zapret-antidpi.lua, …) — приходят
    из import/lua/ в комплекте GUI; защищены от удаления/переименования,
    но могут редактироваться и сбрасываться к bundled-версии;
  - пользовательские *.lua — любые скрипты, созданные/импортированные
    через GUI; полностью управляемые.

Имя скрипта (без расширения .lua) валидируется паттерном
[a-zA-Z0-9_.-]{1,128}.

Использование:
    from core.lua_manager import get_lua_manager
    lm = get_lua_manager()
    code = lm.get_script("zapret-lib")
    lm.save_script("my_script", "print('hello')")
    ok, errors = lm.check_syntax("my_script")
"""

import os
import re
import shutil
import subprocess
import threading

from core.log_buffer import log
from core.config_manager import get_config_manager


# Корень GUI-пакета (для доступа к bundled-скриптам в import/lua)
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLED_LUA_DIR = os.path.join(_APP_DIR, "import", "lua")

# Имя файла: латиница/цифры/_/-/. длиной 1..128
NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")

# Возможные интерпретаторы для проверки синтаксиса
_LUAC_CANDIDATES = (
    "luac", "luac5.4", "luac5.3", "luac5.2", "luac5.1",
    "luac54", "luac53", "luac52", "luac51",
)
_LUA_CANDIDATES = (
    "lua", "lua5.4", "lua5.3", "lua5.2", "lua5.1",
    "lua54", "lua53", "lua52", "lua51",
)


class LuaManager:
    """Управление *.lua файлами."""

    def __init__(self):
        self._lock = threading.Lock()
        self._luac_cache = None  # lazily resolved
        self._lua_cache = None

    # ─── Пути ─────────────────────────────────────────────

    @property
    def lua_path(self):
        cfg = get_config_manager()
        return cfg.get("zapret", "lua_path", default="/opt/zapret2/lua")

    def _file_path(self, name):
        return os.path.join(self.lua_path, name + ".lua")

    def _bundled_path(self, name):
        return os.path.join(BUNDLED_LUA_DIR, name + ".lua")

    def _ensure_dir(self):
        path = self.lua_path
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
                log.info(f"Создана директория lua: {path}", source="lua")
            except OSError as e:
                log.error(f"Не удалось создать {path}: {e}", source="lua")

    # ─── Имя ─────────────────────────────────────────────

    def _validate_name(self, name):
        if not isinstance(name, str):
            return False
        if not NAME_RE.match(name):
            return False
        if name in (".", ".."):
            return False
        return True

    def _is_bundled(self, name):
        return os.path.isfile(self._bundled_path(name))

    # ─── Список / Чтение ─────────────────────────────────

    def list_names(self):
        """Имена всех *.lua файлов (без расширения), bundled + user."""
        names = set()
        # bundled
        if os.path.isdir(BUNDLED_LUA_DIR):
            try:
                for entry in os.listdir(BUNDLED_LUA_DIR):
                    if entry.endswith(".lua"):
                        stem = entry[:-4]
                        if self._validate_name(stem):
                            names.add(stem)
            except OSError as e:
                log.error(f"Не удалось прочитать {BUNDLED_LUA_DIR}: {e}",
                          source="lua")
        # runtime
        path = self.lua_path
        try:
            if os.path.isdir(path):
                for entry in os.listdir(path):
                    if entry.endswith(".lua"):
                        stem = entry[:-4]
                        if self._validate_name(stem):
                            names.add(stem)
        except OSError as e:
            log.error(f"Не удалось прочитать {path}: {e}", source="lua")

        # bundled — первыми по алфавиту, затем чисто-пользовательские
        bundled = sorted(n for n in names if self._is_bundled(n))
        custom = sorted(n for n in names if not self._is_bundled(n))
        return bundled + custom

    def get_script(self, name):
        """Прочитать текст скрипта. Если файла нет, но есть bundled — вернёт его."""
        if not self._validate_name(name):
            return ""

        filepath = self._file_path(name)
        if not os.path.exists(filepath):
            bundled = self._bundled_path(name)
            if os.path.exists(bundled):
                try:
                    with open(bundled, "r", encoding="utf-8", errors="replace") as f:
                        return f.read()
                except Exception as e:
                    log.error(f"Ошибка чтения bundled {name}.lua: {e}",
                              source="lua")
                    return ""
            return ""

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            log.error(f"Ошибка чтения {name}.lua: {e}", source="lua")
            return ""

    def save_script(self, name, content):
        """Сохранить скрипт. Возвращает (bool, error_msg)."""
        if not self._validate_name(name):
            return False, "Недопустимое имя скрипта"

        if not isinstance(content, str):
            return False, "Содержимое должно быть строкой"

        # Лимит 1 MiB — защита от случайной огромной вставки
        if len(content.encode("utf-8")) > 1024 * 1024:
            return False, "Слишком большой файл (>1 МиБ)"

        self._ensure_dir()
        filepath = self._file_path(name)

        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
            size = len(content.encode("utf-8"))
            log.info(f"Сохранён {name}.lua ({size} байт)", source="lua")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка записи {name}.lua: {e}", source="lua")
            return False, str(e)

    def create_script(self, name, content=""):
        """Создать новый Lua-скрипт. Возвращает (bool, error_msg)."""
        if not self._validate_name(name):
            return False, "Недопустимое имя скрипта"

        self._ensure_dir()
        filepath = self._file_path(name)

        if os.path.exists(filepath):
            return False, "Скрипт с таким именем уже существует"

        try:
            with self._lock:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content or "")
            log.info(f"Создан {name}.lua", source="lua")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка создания {name}.lua: {e}", source="lua")
            return False, str(e)

    def rename_script(self, old_name, new_name):
        """Переименовать пользовательский скрипт (bundled — нельзя)."""
        if not self._validate_name(old_name):
            return False, "Недопустимое исходное имя"
        if not self._validate_name(new_name):
            return False, "Недопустимое новое имя"
        if old_name == new_name:
            return False, "Новое имя совпадает со старым"
        if self._is_bundled(old_name):
            return False, "Нельзя переименовать bundled-скрипт"
        if self._is_bundled(new_name):
            return False, "Имя занято bundled-скриптом"

        src = self._file_path(old_name)
        dst = self._file_path(new_name)
        if not os.path.exists(src):
            return False, "Исходный скрипт не существует"
        if os.path.exists(dst):
            return False, "Скрипт с новым именем уже существует"

        try:
            with self._lock:
                os.rename(src, dst)
            log.info(f"{old_name}.lua → {new_name}.lua", source="lua")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка переименования {old_name}.lua: {e}", source="lua")
            return False, str(e)

    def delete_script(self, name):
        """Удалить пользовательский скрипт (bundled — нельзя)."""
        if not self._validate_name(name):
            return False, "Недопустимое имя"
        if self._is_bundled(name):
            return False, "Нельзя удалить bundled-скрипт"

        filepath = self._file_path(name)
        if not os.path.exists(filepath):
            return False, "Скрипт не существует"

        try:
            with self._lock:
                os.remove(filepath)
            log.info(f"Удалён {name}.lua", source="lua")
            return True, ""
        except Exception as e:
            log.error(f"Ошибка удаления {name}.lua: {e}", source="lua")
            return False, str(e)

    def reset_to_bundled(self, name):
        """Восстановить bundled-версию скрипта (если он был изменён)."""
        if not self._validate_name(name):
            return False, "Недопустимое имя"
        if not self._is_bundled(name):
            return False, "Скрипт не является bundled (нет дефолта)"

        bundled = self._bundled_path(name)
        try:
            with open(bundled, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return False, f"Ошибка чтения bundled: {e}"

        ok, err = self.save_script(name, content)
        if ok:
            log.info(f"Сброшен {name}.lua к bundled-версии", source="lua")
        return ok, err

    def get_stats(self):
        """Статистика по всем скриптам: {name: {...}}."""
        stats = {}
        for name in self.list_names():
            filepath = self._file_path(name)
            exists = os.path.exists(filepath)
            is_bundled = self._is_bundled(name)
            size = 0
            lines = 0
            modified = 0
            if exists:
                try:
                    size = os.path.getsize(filepath)
                    modified = int(os.path.getmtime(filepath))
                    with open(filepath, "rb") as f:
                        for _ in f:
                            lines += 1
                except Exception:
                    pass
            elif is_bundled:
                bp = self._bundled_path(name)
                try:
                    size = os.path.getsize(bp)
                    with open(bp, "rb") as f:
                        for _ in f:
                            lines += 1
                except Exception:
                    pass

            writable = (
                os.access(os.path.dirname(filepath), os.W_OK)
                if os.path.isdir(os.path.dirname(filepath)) else True
            )
            modified_from_bundled = False
            if exists and is_bundled:
                try:
                    modified_from_bundled = not _files_equal(
                        filepath, self._bundled_path(name)
                    )
                except Exception:
                    modified_from_bundled = False

            stats[name] = {
                "name": name,
                "filename": name + ".lua",
                "path": filepath,
                "size": size,
                "lines": lines,
                "exists": exists,
                "writable": writable,
                "is_builtin": is_bundled,
                "modified": modified,
                "modified_from_bundled": modified_from_bundled,
            }
        return stats

    # ─── Проверка синтаксиса ─────────────────────────────

    def _resolve_luac(self):
        if self._luac_cache is not None:
            return self._luac_cache or None
        for cand in _LUAC_CANDIDATES:
            path = shutil.which(cand)
            if path:
                self._luac_cache = path
                return path
        self._luac_cache = ""
        return None

    def _resolve_lua(self):
        if self._lua_cache is not None:
            return self._lua_cache or None
        for cand in _LUA_CANDIDATES:
            path = shutil.which(cand)
            if path:
                self._lua_cache = path
                return path
        self._lua_cache = ""
        return None

    def check_syntax(self, name=None, content=None):
        """
        Проверить синтаксис Lua-скрипта.

        Можно передать либо name (тогда читается файл), либо content
        (тогда проверяется текст напрямую).

        Returns:
            dict {
                "ok": bool,
                "errors": [{"line": int|None, "message": str}, ...],
                "checker": "luac" | "lua" | "builtin",
                "warnings": [str, ...],   # необязательно
            }
        """
        if content is None:
            if not self._validate_name(name or ""):
                return {
                    "ok": False,
                    "errors": [{"line": None, "message": "Недопустимое имя"}],
                    "checker": "builtin",
                }
            filepath = self._file_path(name)
            if not os.path.exists(filepath):
                return {
                    "ok": False,
                    "errors": [{"line": None, "message": "Файл не существует"}],
                    "checker": "builtin",
                }
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                return {
                    "ok": False,
                    "errors": [{"line": None, "message": f"Ошибка чтения: {e}"}],
                    "checker": "builtin",
                }

        if not isinstance(content, str):
            return {
                "ok": False,
                "errors": [{"line": None, "message": "Содержимое должно быть строкой"}],
                "checker": "builtin",
            }

        # 1) luac -p (предпочтительно)
        luac = self._resolve_luac()
        if luac:
            return _check_with_luac(luac, content)

        # 2) lua -e 'loadstring' fallback
        lua = self._resolve_lua()
        if lua:
            return _check_with_lua(lua, content)

        # 3) Чисто Python-проверка
        return _builtin_check(content)


# ═══════════════════ Helpers ═══════════════════

def _files_equal(a, b):
    """Сравнить два файла побайтно (для маленьких lua-файлов это ок)."""
    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            return fa.read() == fb.read()
    except Exception:
        return False


def _check_with_luac(luac_path, content):
    """Проверить через `luac -p -` (читает stdin)."""
    try:
        p = subprocess.Popen(
            [luac_path, "-p", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = p.communicate(input=content.encode("utf-8"), timeout=10)
        if p.returncode == 0:
            return {"ok": True, "errors": [], "checker": "luac"}
        return _parse_luac_errors(stderr.decode("utf-8", errors="replace"), "luac")
    except FileNotFoundError:
        return _builtin_check(content)
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        return {
            "ok": False,
            "errors": [{"line": None, "message": "luac: timeout (>10s)"}],
            "checker": "luac",
        }
    except Exception as e:
        return {
            "ok": False,
            "errors": [{"line": None, "message": f"luac: {e}"}],
            "checker": "luac",
        }


def _check_with_lua(lua_path, content):
    """Использовать `lua -e 'loadstring/load'` для проверки."""
    # Передаём код через stdin как chunk; loadstring (5.1) или load (5.2+).
    probe = (
        "local s=io.read('*a'); "
        "local f,err=load and load(s) or loadstring(s); "
        "if not f then io.stderr:write(err) os.exit(1) end"
    )
    try:
        p = subprocess.Popen(
            [lua_path, "-e", probe],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = p.communicate(input=content.encode("utf-8"), timeout=10)
        if p.returncode == 0:
            return {"ok": True, "errors": [], "checker": "lua"}
        return _parse_luac_errors(stderr.decode("utf-8", errors="replace"), "lua")
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        return {
            "ok": False,
            "errors": [{"line": None, "message": "lua: timeout (>10s)"}],
            "checker": "lua",
        }
    except Exception as e:
        return {
            "ok": False,
            "errors": [{"line": None, "message": f"lua: {e}"}],
            "checker": "lua",
        }


# Формат ошибок luac/lua:
#   luac: stdin:12: '=' expected near 'end'
#   lua: [string "..."]:7: '<eof>' expected near 'else'
_LUAC_ERR_RE = re.compile(
    r"^(?:[a-zA-Z0-9_./-]+:\s*)?"
    r"(?:\[[^\]]+\]:|stdin:|\-:)?"
    r"\s*(\d+):\s*(.*)$"
)


def _parse_luac_errors(stderr, checker):
    errors = []
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _LUAC_ERR_RE.match(line)
        if m:
            try:
                ln = int(m.group(1))
            except ValueError:
                ln = None
            msg = m.group(2).strip() or line
            errors.append({"line": ln, "message": msg})
        else:
            errors.append({"line": None, "message": line})
    if not errors:
        errors.append({"line": None, "message": "Неизвестная ошибка синтаксиса"})
    return {"ok": False, "errors": errors, "checker": checker}


# ─── Чисто Python-проверка ────────────────────────────────

# Ключевые слова, открывающие/закрывающие блоки Lua
_OPEN_KW = {"function", "do", "if", "for", "while", "repeat"}
# `then` тоже открывает уровень (закрывается end), но появляется в сочетании
# с if/elseif. Мы считаем if/elseif/then как один уровень — закрываемый end.
# В упрощённой модели: считаем баланс { do, function, if-then, for, while }
# как единый стек "end-блоков", плюс отдельно repeat..until.

_TOKEN_RE = re.compile(
    r"""
    (?P<lcomment>--\[(?P<lcdash>=*)\[.*?\](?P=lcdash)\])     # long comment
    | (?P<scomment>--[^\n]*)                                 # short comment
    | (?P<lstring>\[(?P<lsdash>=*)\[.*?\](?P=lsdash)\])      # long string
    | (?P<sstring>"(?:\\.|[^"\\\n])*")                       # double-quoted
    | (?P<aposstring>'(?:\\.|[^'\\\n])*')                    # single-quoted
    | (?P<word>[A-Za-z_][A-Za-z_0-9]*)                       # identifier/keyword
    | (?P<num>\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)               # number
    | (?P<paren>[(){}\[\]])                                  # bracket
    | (?P<ws>\s+)                                            # whitespace
    | (?P<rest>.)                                            # everything else
    """,
    re.VERBOSE | re.DOTALL,
)


def _builtin_check(content):
    """
    Базовая проверка синтаксиса без интерпретатора Lua.

    Покрывает:
      - несбалансированные скобки (), [], {},
      - несбалансированные блоки function/do/if/for/while…end и repeat…until.

    Не ловит более тонкие синтаксические ошибки (как `=` ожидался и т.п.) —
    для этого нужен полноценный luac.
    """
    errors = []
    warnings = []

    # Стек "end-блоков": элементы — (line, kind)
    end_stack = []
    until_stack = []  # repeat..until
    paren_stack = []  # (char, line)

    # Флаг: ожидаем `do` после `for`/`while` — этот do принадлежит им,
    # отдельный блок не открывает.
    pending_do = False

    line_starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            line_starts.append(i + 1)

    def line_at(pos):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    pos = 0
    L = len(content)

    while pos < L:
        m = _TOKEN_RE.match(content, pos)
        if not m:
            pos += 1
            continue

        kind = m.lastgroup
        tok = m.group(0)
        ln = line_at(pos)

        if kind in ("lcomment", "scomment", "lstring",
                    "sstring", "aposstring", "num", "ws", "rest"):
            pos = m.end()
            continue

        if kind == "paren":
            if tok in "([{":
                paren_stack.append((tok, ln))
            else:
                if not paren_stack:
                    errors.append({
                        "line": ln,
                        "message": f"Лишняя закрывающая скобка '{tok}'",
                    })
                else:
                    open_ch, open_ln = paren_stack.pop()
                    pair = {"(": ")", "[": "]", "{": "}"}[open_ch]
                    if pair != tok:
                        errors.append({
                            "line": ln,
                            "message": (
                                f"Несоответствие скобок: открыта '{open_ch}' "
                                f"на строке {open_ln}, закрыта '{tok}'"
                            ),
                        })
            pos = m.end()
            continue

        if kind == "word":
            if tok == "function":
                end_stack.append((ln, "function"))
            elif tok == "do":
                # `for ... do` / `while ... do` — do принадлежит им
                if pending_do:
                    pending_do = False
                else:
                    end_stack.append((ln, "do"))
            elif tok == "if":
                end_stack.append((ln, "if"))
            elif tok == "for":
                end_stack.append((ln, "for"))
                pending_do = True
            elif tok == "while":
                end_stack.append((ln, "while"))
                pending_do = True
            elif tok == "repeat":
                until_stack.append(ln)
            elif tok == "until":
                if not until_stack:
                    errors.append({
                        "line": ln,
                        "message": "'until' без 'repeat'",
                    })
                else:
                    until_stack.pop()
            elif tok == "end":
                if not end_stack:
                    errors.append({
                        "line": ln,
                        "message": "Лишний 'end'",
                    })
                else:
                    end_stack.pop()
            # then/else/elseif — внутри if-блока, отдельный уровень не нужен.
            pos = m.end()
            continue

        pos = m.end()

    # Незакрытые блоки
    for ln, kind in end_stack:
        errors.append({
            "line": ln,
            "message": f"Незакрытый блок '{kind}' (нет 'end')",
        })
    for ln in until_stack:
        errors.append({
            "line": ln,
            "message": "Незакрытый 'repeat' (нет 'until')",
        })
    for ch, ln in paren_stack:
        pair = {"(": ")", "[": "]", "{": "}"}[ch]
        errors.append({
            "line": ln,
            "message": f"Незакрытая '{ch}' (нет '{pair}')",
        })

    if not errors:
        warnings.append(
            "Базовая проверка пройдена, но lua/luac не найдены — "
            "тонкие синтаксические ошибки могут быть пропущены."
        )

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "checker": "builtin",
    }


# ═══════════════════ Singleton ═══════════════════

_instance = None
_instance_lock = threading.Lock()


def get_lua_manager():
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = LuaManager()
    return _instance
