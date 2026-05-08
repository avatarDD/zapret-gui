/**
 * lua_syntax.js — Подсветка синтаксиса Lua для отображения в HTML.
 *
 * Возвращает строку HTML с обёрнутыми токенами в <span class="lua-…">.
 * Используется через overlay над <textarea> на странице lua_scripts.js.
 *
 * CSS-классы (определены в style.css):
 *   .lua-kw       — ключевое слово (function, end, if, local, …)
 *   .lua-builtin  — встроенная функция/таблица (print, ipairs, math, table, …)
 *   .lua-string   — строковый литерал
 *   .lua-comment  — комментарий
 *   .lua-num      — числовой литерал
 *   .lua-op       — оператор
 *   .lua-func     — имя в позиции вызова (foo() / obj:foo())
 */

const LuaSyntax = (() => {

    const KEYWORDS = new Set([
        'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
        'function', 'goto', 'if', 'in', 'local', 'nil', 'not', 'or',
        'repeat', 'return', 'then', 'true', 'until', 'while',
    ]);

    const BUILTINS = new Set([
        // Standard library namespaces
        'string', 'table', 'math', 'io', 'os', 'coroutine', 'package',
        'debug', 'utf8', 'bit', 'bit32',
        // Globals
        'print', 'ipairs', 'pairs', 'next', 'select', 'type', 'tostring',
        'tonumber', 'error', 'assert', 'pcall', 'xpcall', 'rawget',
        'rawset', 'rawequal', 'rawlen', 'setmetatable', 'getmetatable',
        'require', 'dofile', 'loadfile', 'load', 'loadstring',
        'unpack', 'collectgarbage', '_G', '_ENV', '_VERSION',
    ]);

    function escapeHtml(s) {
        return s.replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
    }

    function span(cls, text) {
        return '<span class="' + cls + '">' + escapeHtml(text) + '</span>';
    }

    /**
     * Подсветить Lua-код. Возвращает HTML-строку.
     * @param {string} src
     * @returns {string}
     */
    function highlight(src) {
        if (!src) return '';
        let i = 0;
        const L = src.length;
        let out = '';

        while (i < L) {
            const ch = src[i];
            const two = src.substr(i, 2);

            // Длинный комментарий: --[[ ... ]] / --[=[...]=]
            if (two === '--') {
                const m = src.substr(i).match(/^--\[(=*)\[/);
                if (m) {
                    const eq = m[1];
                    const close = ']' + eq + ']';
                    const startTok = i;
                    const after = i + m[0].length;
                    const end = src.indexOf(close, after);
                    if (end === -1) {
                        // незакрытый комментарий — до конца файла
                        out += span('lua-comment', src.substring(startTok));
                        i = L;
                    } else {
                        out += span('lua-comment',
                            src.substring(startTok, end + close.length));
                        i = end + close.length;
                    }
                    continue;
                }
                // Короткий комментарий до конца строки
                let nl = src.indexOf('\n', i);
                if (nl === -1) nl = L;
                out += span('lua-comment', src.substring(i, nl));
                i = nl;
                continue;
            }

            // Длинная строка [[...]] / [=[...]=]
            if (ch === '[') {
                const m = src.substr(i).match(/^\[(=*)\[/);
                if (m) {
                    const eq = m[1];
                    const close = ']' + eq + ']';
                    const startTok = i;
                    const after = i + m[0].length;
                    const end = src.indexOf(close, after);
                    if (end === -1) {
                        out += span('lua-string', src.substring(startTok));
                        i = L;
                    } else {
                        out += span('lua-string',
                            src.substring(startTok, end + close.length));
                        i = end + close.length;
                    }
                    continue;
                }
            }

            // Обычные строки "..." / '...'
            if (ch === '"' || ch === "'") {
                const quote = ch;
                let j = i + 1;
                while (j < L) {
                    if (src[j] === '\\') { j += 2; continue; }
                    if (src[j] === '\n') break;
                    if (src[j] === quote) { j++; break; }
                    j++;
                }
                out += span('lua-string', src.substring(i, j));
                i = j;
                continue;
            }

            // Hex/числа: 0x[0-9a-fA-F]+ или 123 / 1.23 / 1e5
            if (/[0-9]/.test(ch) ||
                (ch === '.' && /[0-9]/.test(src[i + 1] || ''))) {
                const m = src.substr(i).match(
                    /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|\.\d+(?:[eE][+\-]?\d+)?)/
                );
                if (m) {
                    out += span('lua-num', m[0]);
                    i += m[0].length;
                    continue;
                }
            }

            // Идентификатор / ключевое слово
            if (/[A-Za-z_]/.test(ch)) {
                const m = src.substr(i).match(/^[A-Za-z_][A-Za-z_0-9]*/);
                if (m) {
                    const word = m[0];
                    if (KEYWORDS.has(word)) {
                        out += span('lua-kw', word);
                    } else if (BUILTINS.has(word)) {
                        out += span('lua-builtin', word);
                    } else {
                        // Если за идентификатором сразу '(' — это вызов
                        const next = src.charAt(i + word.length);
                        if (next === '(' || next === '{' || next === '"' || next === "'") {
                            out += span('lua-func', word);
                        } else {
                            out += escapeHtml(word);
                        }
                    }
                    i += word.length;
                    continue;
                }
            }

            // Операторы — последовательность из спец-символов
            if ('+-*/%^#=~<>;:,.()[]{}'.indexOf(ch) >= 0) {
                // двусимвольные операторы
                const t2 = src.substr(i, 2);
                if (['==', '~=', '<=', '>=', '..', '::'].indexOf(t2) >= 0) {
                    out += span('lua-op', t2);
                    i += 2;
                    continue;
                }
                if ('+-*/%^#=~<>'.indexOf(ch) >= 0) {
                    out += span('lua-op', ch);
                    i += 1;
                    continue;
                }
                // знаки пунктуации не подсвечиваем (нейтральны)
                out += escapeHtml(ch);
                i += 1;
                continue;
            }

            // всё остальное — как есть
            out += escapeHtml(ch);
            i += 1;
        }

        return out;
    }

    return { highlight };
})();
