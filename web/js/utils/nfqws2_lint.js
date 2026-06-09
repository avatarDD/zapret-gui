/**
 * nfqws2_lint.js — Токенизатор + анализатор стратегий nfqws2.
 *
 * Превращает строку args одного профиля в:
 *   - токены с позициями (для подсветки и наведения),
 *   - диагностику ошибок/предупреждений (start/end/severity/message),
 *   - документацию по токену под курсором (для боковой панели),
 *   - структуру (какие слоты скелета заполнены — для схемы профиля).
 *
 * Зависит от Nfqws2Spec. Только nfqws2 (никакого nfqws1).
 *
 * Экспорт: глобальный Nfqws2Lint (+ module.exports для node-тестов).
 */
const Nfqws2Lint = (() => {

    const Spec = (typeof Nfqws2Spec !== 'undefined')
        ? Nfqws2Spec
        : (typeof require !== 'undefined' ? require('./nfqws2_spec.js') : null);

    const SEV = { ERROR: 'error', WARN: 'warn', INFO: 'info' };

    // ──────────────── Токенизация ────────────────
    // Разбиваем по пробелам, сохраняя позиции. Кавычки не разбиваем (Lua-литералы).

    function tokenize(text) {
        const tokens = [];
        const re = /\S+/g;
        let m;
        while ((m = re.exec(text)) !== null) {
            tokens.push({ raw: m[0], start: m.index, end: m.index + m[0].length });
        }
        return tokens;
    }

    // Разобрать один токен в структурированный вид.
    // Виды: 'flag' (--x[=v]), 'cont' (^/\), 'bare' (что-то без --).
    function classifyToken(tok) {
        const raw = tok.raw;
        if (raw === '^' || raw === '\\') return { kind: 'cont', tok };
        const fm = raw.match(/^(--[A-Za-z0-9-]+)(=([\s\S]*))?$/);
        if (fm) {
            return {
                kind: 'flag',
                tok,
                flag: fm[1],
                hasEq: fm[2] !== undefined,
                value: fm[3] !== undefined ? fm[3] : null,
                valueStart: fm[2] !== undefined ? tok.start + fm[1].length + 1 : tok.end,
            };
        }
        return { kind: 'bare', tok };
    }

    // ──────────────── Валидаторы значений ────────────────

    function isInt(s) { return /^-?\d+$/.test(s); }
    function isPorts(s) {
        if (s === '*') return true;
        return s.split(',').every(p => /^~?\d+(-\d+)?$/.test(p.trim()) && p.trim() !== '');
    }
    // Диапазон --in/out-range: [mode<int>](-|<)[mode<int>] ; одиночный 'a'/'x' тоже ок.
    function isRange(s) {
        if (/^[ax]$/.test(s)) return true;
        const part = '(?:[axnbsdp]|[nbsdp]\\d+|\\d+)';
        const re = new RegExp('^(?:' + part + ')?[-<](?:' + part + ')?$');
        if (re.test(s)) return true;
        // одиночная граница без разделителя: -d10 уже покрыт (пустая левая часть)
        return false;
    }
    // pos-маркер (один): число | ±число | marker[±N]
    function isPosMarker(s) {
        if (/^-?\d+$/.test(s)) return true;
        const m = s.match(/^([a-z]+)([+-]\d+)?$/);
        return !!(m && Spec.POS_MARKERS.indexOf(m[1]) >= 0);
    }

    // Проверка значения по типу arg. Возвращает null (ок) или строку-ошибку.
    function checkValueType(type, value, valuesEnum) {
        if (value === '' || value == null) return null; // пустое допустимо у многих
        switch (type) {
            case 'int':
                return isInt(value) ? null : 'ожидается целое число';
            case 'ports':
                return isPorts(value) ? null : 'ожидается порт/диапазон (80, 443, 50000-50100, *)';
            case 'range':
                return isRange(value) ? null
                    : 'неверный диапазон (примеры: -d10, -s5556, s100-s1000, a, x)';
            case 'enum':
                if (valuesEnum && valuesEnum.indexOf(value) < 0)
                    return 'недопустимое значение (ожидается: ' + valuesEnum.join(', ') + ')';
                return null;
            case 'csv-enum': {
                if (!valuesEnum) return null;
                const bad = value.split(',').map(v => v.trim()).filter(v => v && valuesEnum.indexOf(v) < 0);
                return bad.length ? 'неизвестно: ' + bad.join(', ') : null;
            }
            case 'pos': {
                const bad = value.split(',').map(v => v.trim()).filter(v => v && !isPosMarker(v));
                return bad.length ? 'неверный маркер позиции: ' + bad.join(', ') : null;
            }
            case 'tls_mod': {
                const bad = value.split(',').map(v => v.trim()).filter(v => {
                    if (!v) return false;
                    const key = v.indexOf('=') >= 0 ? v.slice(0, v.indexOf('=')) : v;
                    return Spec.TLS_MODS.indexOf(key) < 0;
                });
                return bad.length ? 'неизвестная tls_mod: ' + bad.join(', ') : null;
            }
            case 'blob-decl':
                return /^[A-Za-z0-9_]+:(?:\+?\d+@.+|@.+|0x[0-9A-Fa-f]+)$/.test(value)
                    ? null : 'формат: NAME:@/path|NAME:0xHEX';
            default:
                return null; // string/file/blob/pattern/csv-* — не проверяем строго
        }
    }

    // ──────────────── Разбор lua-цепочки (--lua-desync=fn:a=b:flag) ────────────────

    function splitChain(value) {
        // Разбиваем по ':' но не внутри кавычек (code='a:b').
        const parts = [];
        let cur = '', q = null, startRel = 0;
        for (let i = 0; i < value.length; i++) {
            const c = value[i];
            if (q) { if (c === q) q = null; cur += c; continue; }
            if (c === '"' || c === "'") { q = c; cur += c; continue; }
            if (c === ':') { parts.push({ text: cur, rel: startRel }); cur = ''; startRel = i + 1; continue; }
            cur += c;
        }
        parts.push({ text: cur, rel: startRel });
        return parts;
    }

    // Диагностика lua-цепочки. base = абсолютная позиция начала value.
    function lintLuaChain(value, base, diags) {
        const parts = splitChain(value);
        if (!parts.length) return;
        const fnName = parts[0].text;
        const fnStart = base + parts[0].rel;
        if (fnName === '') {
            diags.push({ start: fnStart, end: fnStart, severity: SEV.ERROR,
                message: '--lua-desync= требует имя функции' });
            return;
        }
        if (!Spec.isKnownFunc(fnName)) {
            diags.push({ start: fnStart, end: fnStart + fnName.length, severity: SEV.ERROR,
                message: 'неизвестная desync-функция «' + fnName + '». '
                    + 'Доступные определены в zapret-antidpi.lua и расширениях проекта.' });
            // продолжаем разбор sub-arg как для неизвестной (без строгой проверки)
        }
        const allowed = Spec.subargsFor(fnName);
        for (let i = 1; i < parts.length; i++) {
            const p = parts[i];
            const txt = p.text;
            const abs = base + p.rel;
            if (txt === '') continue; // пустой сегмент (двойное ::) — терпим
            const eq = txt.indexOf('=');
            const key = eq >= 0 ? txt.slice(0, eq) : txt;
            const val = eq >= 0 ? txt.slice(eq + 1) : null;
            // только для известных функций проверяем имена sub-arg строго
            if (Spec.isKnownFunc(fnName) && !Object.prototype.hasOwnProperty.call(allowed, key)) {
                diags.push({ start: abs, end: abs + key.length, severity: SEV.WARN,
                    message: 'неизвестный параметр «' + key + '» для ' + fnName });
                continue;
            }
            const spec = allowed[key];
            if (spec && val !== null) {
                const valuesEnum = spec.values || Spec.valuesForSubargType(spec.type);
                const err = checkValueType(spec.type, val, spec.values);
                if (err) {
                    diags.push({ start: abs + key.length + 1, end: abs + txt.length,
                        severity: SEV.WARN, message: key + ': ' + err });
                } else if (valuesEnum && spec.type && spec.type.indexOf('lua-') === 0
                    && valuesEnum.indexOf(val) < 0) {
                    diags.push({ start: abs + key.length + 1, end: abs + txt.length,
                        severity: SEV.INFO,
                        message: key + ': «' + val + '» не из известных ('
                            + valuesEnum.slice(0, 4).join(', ') + '…)' });
                }
            }
            if (spec && spec.type === 'flag' && val !== null && key !== 'tcp_md5'
                && key !== 'ip6_hopbyhop') {
                diags.push({ start: abs, end: abs + txt.length, severity: SEV.INFO,
                    message: key + ' — флаг без значения' });
            }
        }
    }

    // ──────────────── Главный анализ профиля ────────────────
    //
    // Возвращает {
    //   tokens: [{...classify, diag?}],
    //   diagnostics: [{start,end,severity,message}],
    //   slots: Set<slot>,            // какие слоты скелета заполнены
    //   order: [slot,...],           // последовательность встреченных слотов
    //   funcs: [имена desync-функций],
    // }

    function analyze(text) {
        const diagnostics = [];
        const tokens = tokenize(text).map(classifyToken);
        const slots = new Set();
        const order = [];
        const funcs = [];
        let sawDesync = false;
        let sawNew = false;

        tokens.forEach((ct) => {
            if (ct.kind === 'cont') return;
            if (ct.kind === 'bare') {
                diagnostics.push({ start: ct.tok.start, end: ct.tok.end, severity: SEV.ERROR,
                    message: 'не похоже на параметр nfqws2 (ожидается --флаг). '
                        + 'Незакавыченный пробел в значении?' });
                ct.diag = SEV.ERROR;
                return;
            }
            // flag
            const fspec = Spec.flag(ct.flag);
            if (!fspec) {
                diagnostics.push({ start: ct.tok.start, end: ct.tok.start + ct.flag.length,
                    severity: SEV.ERROR,
                    message: 'неизвестный флаг «' + ct.flag + '» (nfqws2). '
                        + 'Проверьте написание — legacy nfqws1 (--dpi-desync*) не поддерживается.' });
                ct.diag = SEV.ERROR;
                return;
            }
            // слот/структура
            if (fspec.slot) {
                slots.add(fspec.slot);
                if (order[order.length - 1] !== fspec.slot) order.push(fspec.slot);
            }
            if (ct.flag === '--new') { sawNew = true; }

            // требование значения
            const needsVal = fspec.arg && !fspec.arg.optional;
            if (needsVal && !ct.hasEq) {
                diagnostics.push({ start: ct.tok.start, end: ct.tok.end, severity: SEV.ERROR,
                    message: ct.flag + ' требует значение (' + ct.flag + '=…)' });
                ct.diag = SEV.ERROR;
                return;
            }
            if (!fspec.arg && ct.hasEq) {
                diagnostics.push({ start: ct.tok.start, end: ct.tok.end, severity: SEV.WARN,
                    message: ct.flag + ' — флаг без значения' });
                ct.diag = SEV.WARN;
            }

            // разбор значения
            if (ct.hasEq && fspec.arg) {
                if (ct.flag === '--lua-desync') {
                    sawDesync = true;
                    const before = diagnostics.length;
                    lintLuaChain(ct.value, ct.valueStart, diagnostics);
                    const firstFn = splitChain(ct.value)[0];
                    if (firstFn) funcs.push(firstFn.text);
                    if (diagnostics.slice(before).some(d => d.severity === SEV.ERROR)) ct.diag = SEV.ERROR;
                    else if (diagnostics.slice(before).some(d => d.severity === SEV.WARN)) ct.diag = SEV.WARN;
                } else if (ct.flag === '--blob') {
                    const err = checkValueType('blob-decl', ct.value);
                    if (err) {
                        diagnostics.push({ start: ct.valueStart, end: ct.tok.end,
                            severity: SEV.WARN, message: '--blob: ' + err });
                        ct.diag = SEV.WARN;
                    }
                } else {
                    const err = checkValueType(fspec.arg.type, ct.value, fspec.arg.values);
                    if (err) {
                        diagnostics.push({ start: ct.valueStart, end: ct.tok.end,
                            severity: SEV.WARN, message: ct.flag + ': ' + err });
                        ct.diag = SEV.WARN;
                    }
                }
            }
        });

        // ── структурные предупреждения ──
        // desync без фильтра/payload → применится ко всему трафику очереди.
        if (sawDesync && !slots.has('filter') && !slots.has('range')) {
            diagnostics.push({ start: 0, end: 0, severity: SEV.WARN, structural: true,
                message: 'Есть приём (--lua-desync), но нет ни --filter-*, ни --payload — '
                    + 'десинк применится ко всему трафику очереди. Ограничьте порт/протокол.' });
        }
        // нет include-списка/доменов → стратегия работает на весь трафик
        // под --filter-*. Это НЕ ошибка (так задуманы авто/circular-стратегии):
        // other.txt больше не подставляется автоматически. Просто инфо.
        if (sawDesync && slots.has('filter') && !slots.has('list')) {
            diagnostics.push({ start: 0, end: 0, severity: SEV.INFO, structural: true,
                message: 'Список доменов/IP не указан — стратегия применяется ко всему '
                    + 'трафику на портах фильтра (исключения netrogat учитываются отдельно). '
                    + 'Чтобы сузить — добавьте --hostlist=… или --hostlist-domains=…' });
        }
        // порядок: desync должен идти после filter (мягко).
        const di = order.indexOf('desync');
        const fi = order.indexOf('filter');
        if (di >= 0 && fi >= 0 && di < fi) {
            diagnostics.push({ start: 0, end: 0, severity: SEV.INFO, structural: true,
                message: 'Рекомендуемый порядок: фильтры → домены/IP → диапазон/payload → --lua-desync.' });
        }

        return { tokens, diagnostics, slots, order, funcs, sawNew };
    }

    // ──────────────── Документация по токену под курсором ────────────────
    //
    // Возвращает объект для боковой панели:
    //   { title, kind, signature?, type?, values?, examples?, desc, file?, group? }
    // или null, если под курсором нет распознаваемого токена.

    function docAt(text, cursor) {
        const tokens = tokenize(text);
        let tok = null;
        for (const t of tokens) {
            if (cursor >= t.start && cursor <= t.end) { tok = t; break; }
        }
        if (!tok) return null;
        const ct = classifyToken(tok);
        if (ct.kind !== 'flag') return null;

        // позиция курсора относительно value
        const inValue = ct.hasEq && cursor >= ct.valueStart;

        if (ct.flag === '--lua-desync' && inValue) {
            return docForLuaChain(ct.value, ct.valueStart, cursor);
        }

        const fspec = Spec.flag(ct.flag);
        if (!fspec) {
            return { title: ct.flag, kind: 'unknown',
                desc: 'Неизвестный флаг nfqws2. Возможно опечатка или это legacy nfqws1 (не поддерживается).' };
        }
        const arg = fspec.arg;
        return {
            title: ct.flag, kind: 'flag', slot: fspec.slot,
            slotLabel: Spec.SLOT_LABELS[fspec.slot],
            signature: arg ? (ct.flag + '=<' + (arg.type) + '>' + (arg.optional ? ' (необязательно)' : ''))
                : ct.flag + ' (без значения)',
            type: arg ? arg.type : null,
            values: arg ? (arg.values || Spec.valuesForSubargType(arg.type)) : null,
            examples: arg ? arg.ex : null,
            desc: fspec.desc,
        };
    }

    function docForLuaChain(value, base, cursor) {
        const parts = splitChain(value);
        const fnName = parts[0].text;
        // курсор внутри имени функции?
        const fnAbsEnd = base + parts[0].rel + parts[0].text.length;
        if (cursor <= fnAbsEnd) {
            const fn = Spec.func(fnName);
            if (!fn) return { title: fnName || '(функция)', kind: 'func-unknown',
                desc: 'Неизвестная desync-функция. Доступные — в zapret-antidpi.lua и расширениях.' };
            return {
                title: fnName, kind: 'func', file: fn.file, cat: fn.cat,
                signature: buildFuncSignature(fnName, fn),
                desc: fn.desc,
                payload: fn.payload,
                groups: fn.groups,
                argList: Object.entries(fn.args || {}).map(([k, v]) =>
                    ({ name: k, type: v.type, desc: v.desc || '', values: v.values, ex: v.ex })),
            };
        }
        // курсор внутри какого-то sub-arg
        let target = null;
        for (let i = 1; i < parts.length; i++) {
            const s = base + parts[i].rel;
            const e = s + parts[i].text.length;
            if (cursor >= s && cursor <= e) { target = parts[i]; break; }
        }
        if (!target) return null;
        const eq = target.text.indexOf('=');
        const key = eq >= 0 ? target.text.slice(0, eq) : target.text;
        const allowed = Spec.subargsFor(fnName);
        const spec = allowed[key];
        if (!spec) return { title: key, kind: 'subarg-unknown',
            desc: 'Неизвестный параметр для ' + fnName + '.' };
        return {
            title: key, kind: 'subarg', forFunc: fnName, group: spec.kind,
            signature: spec.type === 'flag' ? (key + ' (флаг)') : (key + '=<' + spec.type + '>'),
            type: spec.type,
            values: spec.values || Spec.valuesForSubargType(spec.type),
            examples: spec.ex,
            desc: spec.desc || '',
        };
    }

    function buildFuncSignature(name, fn) {
        const args = Object.entries(fn.args || {}).map(([k, v]) =>
            v.type === 'flag' ? k : (k + '=' + (v.type)));
        const groupHint = (fn.groups && fn.groups.length)
            ? ' [+' + fn.groups.join('/') + ']' : '';
        return name + (args.length ? ':' + args.join(':') : '') + groupHint;
    }

    return {
        SEV, tokenize, classifyToken, analyze, docAt,
        splitChain, isRange, isPorts, isPosMarker, checkValueType,
    };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = Nfqws2Lint;
