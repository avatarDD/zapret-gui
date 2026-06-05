/**
 * syntax.js — Подсветка синтаксиса стратегий nfqws2 (ТОЛЬКО nfqws2).
 *
 * Источник данных — Nfqws2Spec (web/js/utils/nfqws2_spec.js). Никакого
 * legacy nfqws1 (--dpi-desync*): движок другой (SKILL §1).
 *
 * Публичный API (используется страницами logs/control/dashboard/strategies):
 *   highlight(text, opts)                  — подсветить строку args
 *   highlightCommand(text, opts)           — подсветить многострочную команду
 *   highlightInLog(text, opts) | null      — подсветить строку лога, если это args
 *   hasNfqwsArgs(text) → bool
 *   highlightWithDiagnostics(text, diags)  — подсветка + классы ошибок (.nfq-error/.nfq-warn)
 *                                            для встроенного редактора (overlay)
 *
 * CSS-классы (style.css): .nfq-binary .nfq-flag .nfq-eq .nfq-value .nfq-method
 *   .nfq-sub-sep .nfq-subkey .nfq-subval .nfq-subflag .nfq-new .nfq-file
 *   .nfq-num .nfq-proto .nfq-pos .nfq-comma .nfq-cont .nfq-error .nfq-warn
 */

const NfqwsSyntax = (() => {

    const Spec = (typeof Nfqws2Spec !== 'undefined') ? Nfqws2Spec : null;

    // Подмножества для подсветки значений-перечислений «как протокол/позиция».
    const L7_SET = new Set(Spec ? Spec.L7_PROTOS : []);
    const PAYLOAD_SET = new Set(Spec ? Spec.PAYLOAD_TYPES : []);

    // ══════════════════ Базовая подсветка ══════════════════

    function highlight(text, opts = {}) {
        if (!text || typeof text !== 'string') return text || '';
        const escapeFirst = opts.escapeFirst !== false;
        const src = escapeFirst ? escapeHtml(text) : text;
        return src.split(/(\s+)/).map(t => highlightToken(t)).join('');
    }

    // token уже html-escaped (highlight передаёт escaped-куски).
    function highlightToken(token) {
        if (/^\s+$/.test(token) || token === '') return token;
        if (token === '--new') return s('nfq-new', '--new');
        if (/^\/[\w/.-]*nfqws2?\b/.test(token)) return s('nfq-binary', token);
        if (token === '^' || token === '\\') return s('nfq-cont', token);

        // --lua-desync=chain
        let m = token.match(/^(--lua-desync)(=)([\s\S]+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlLuaChain(m[3]);

        // --filter-l7 / --payload — csv протоколов/типов
        m = token.match(/^(--filter-l7|--payload)(=)([\s\S]+)$/);
        if (m) return s('nfq-flag', m[1]) + s('nfq-eq', '=') + hlList(m[3], 'nfq-proto');

        // общий --flag=value
        m = token.match(/^(--[\w-]+)(=)([\s\S]+)$/);
        if (m) {
            let cls = 'nfq-value';
            const v = m[3];
            if (/\.\w{2,4}(?:"|$)/.test(v) || v.indexOf('/') >= 0) cls = 'nfq-file';
            else if (/^-?\d+$/.test(v) || /^0x[0-9A-Fa-f]+$/.test(v)) cls = 'nfq-num';
            return s('nfq-flag', m[1]) + s('nfq-eq', '=') + s(cls, v);
        }

        // --flag (без значения)
        if (/^--[\w-]+$/.test(token)) return s('nfq-flag', token);

        return token;
    }

    function hlLuaChain(chain) {
        return chain.split(':').map((part, i) => {
            const sep = i > 0 ? s('nfq-sub-sep', ':') : '';
            if (i === 0) return sep + s('nfq-method', part);
            const eq = part.indexOf('=');
            if (eq > 0) {
                const k = part.substring(0, eq), v = part.substring(eq + 1);
                const vc = /^-?\d+$/.test(v) ? 'nfq-num'
                    : (/\.\w{2,4}$/.test(v) || v.indexOf('/') >= 0) ? 'nfq-file' : 'nfq-subval';
                return sep + s('nfq-subkey', k) + s('nfq-eq', '=') + s(vc, v);
            }
            return sep + s('nfq-subflag', part);
        }).join('');
    }

    function hlList(val, cls) {
        return val.split(',').map((v, i) => {
            const sep = i > 0 ? s('nfq-comma', ',') : '';
            return sep + s(cls, v);
        }).join('');
    }

    function s(cls, text) { return '<span class="' + cls + '">' + text + '</span>'; }

    // ══════════════════ Многострочная команда ══════════════════

    function highlightCommand(text, opts) {
        if (!text) return text || '';
        return text.split('\n').map(l => highlight(l, opts)).join('\n');
    }

    // ══════════════════ Логи ══════════════════

    function hasNfqwsArgs(text) {
        return text
            ? /--(?:filter-(?:tcp|udp|l[37])|lua-desync|payload|qnum|hostlist|ipset|new|blob)/.test(text)
            : false;
    }

    function highlightInLog(text, opts) {
        return (text && hasNfqwsArgs(text)) ? highlight(text, opts) : null;
    }

    // ══════════════════ Подсветка с диагностикой (overlay-редактор) ══════════════════
    //
    // Возвращает HTML, посимвольно соответствующий исходному тексту (для
    // точного выравнивания каретки), где токены, пересекающие диапазоны
    // ошибок/предупреждений, дополнительно обёрнуты в .nfq-error/.nfq-warn.
    // diagnostics: [{start,end,severity}] (из Nfqws2Lint.analyze).

    function highlightWithDiagnostics(text, diagnostics) {
        if (!text) return '';
        const ranges = (diagnostics || []).filter(d => !d.structural && d.end > d.start);
        // Проходим по токенам с сохранением позиций, чтобы знать пересечения.
        let out = '';
        let pos = 0;
        const partRe = /(\s+)/g;
        // Разбиваем на чередование [пробелы][токен]…; вручную идём по тексту.
        const tokenRe = /\S+|\s+/g;
        let m;
        while ((m = tokenRe.exec(text)) !== null) {
            const piece = m[0];
            const start = m.index;
            const end = start + piece.length;
            if (/^\s+$/.test(piece)) { out += piece; pos = end; continue; }
            const inner = highlightToken(escapeHtml(piece));
            const sev = worstSeverityFor(start, end, ranges);
            if (sev === 'error') out += '<span class="nfq-error">' + inner + '</span>';
            else if (sev === 'warn') out += '<span class="nfq-warn">' + inner + '</span>';
            else out += inner;
            pos = end;
        }
        void partRe; // (оставлено для читабельности; не используется)
        return out;
    }

    function worstSeverityFor(start, end, ranges) {
        let sev = null;
        for (const r of ranges) {
            if (r.start < end && r.end > start) {
                if (r.severity === 'error') return 'error';
                if (r.severity === 'warn') sev = 'warn';
            }
        }
        return sev;
    }

    function escapeHtml(text) {
        if (text == null) return '';
        return String(text)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        highlight, highlightCommand, highlightInLog, hasNfqwsArgs,
        highlightWithDiagnostics, escapeHtml,
    };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = NfqwsSyntax;
