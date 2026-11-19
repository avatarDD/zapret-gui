#!/usr/bin/env node
/**
 * i18n_extract.js — собирает русские строки интерфейса для английского словаря.
 *
 * Интерфейс написан по-русски прямо в коде страниц (web/js/**, web/index.html).
 * Английский режим переводит готовый DOM по словарю «русский текст →
 * английский» (web/js/i18n/en.text.js, см. web/js/utils/i18n.js и
 * docs/i18n.md). Этот скрипт находит в исходниках все строки, которые
 * могут попасть на экран, и приводит их к тому виду, в каком их увидит
 * переводчик DOM:
 *
 *   - строковые литералы '…', "…" и шаблоны `…` с кириллицей;
 *   - `${выражение}` в шаблоне и операнд-не-литерал в цепочке `'а' + x + 'б'`
 *     становятся местами подстановки {0}, {1}, …;
 *   - HTML режется по тегам: каждый текстовый кусок — отдельный ключ,
 *     атрибуты title / placeholder / aria-label / alt / data-tip — тоже;
 *   - пробелы схлопываются, сущности (&nbsp; &laquo; …) раскрываются.
 *
 * Использование:
 *   node tools/i18n_extract.js --check        — код 1, если в словаре нет
 *                                               перевода для какой-то строки
 *   node tools/i18n_extract.js --missing      — недостающие ключи JSON-ом
 *   node tools/i18n_extract.js --stats        — сводка по файлам
 *   node tools/i18n_extract.js --unused       — ключи словаря, которых больше
 *                                               нет в коде (кроме ручных)
 *
 * Как модуль: require('./i18n_extract').extractAll() → Map(ключ → [файлы]).
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const WEB = path.join(ROOT, 'web');
const DICT = path.join(WEB, 'js', 'i18n', 'en.text.js');

// Словари в DOM не рендерятся. Сам переводчик сканируется: его alert и
// confirm тоже должны быть в словаре.
const SKIP_FILES = new Set([
    'js/i18n/ru.js', 'js/i18n/en.js', 'js/i18n/en.text.js',
    'js/i18n/en.server.js',
]);

const CYR = /[А-Яа-яЁё]/;
// Те же атрибуты, что переводит web/js/utils/i18n.js (label — у optgroup,
// value — у кнопок-input).
const TEXT_ATTRS = ['title', 'placeholder', 'aria-label', 'alt', 'data-tip',
    'data-label', 'label'];
const BUTTON_INPUT = /\btype\s*=\s*["']?(button|submit|reset)\b/i;

// ── Токенизатор JS ─────────────────────────────────────────────────
// Достаточно точный для нашего кода: строки, шаблоны с вложенными
// выражениями, комментарии и регулярные выражения (по предыдущему токену).

const REGEX_PREV = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{',
    '}', ';', '+', '-', '*', '%', '<', '>', '~', '^', '=>', '&&', '||', '??',
    '==', '===', '!=', '!==', '+=', '-=', 'return', 'typeof', 'case', 'do',
    'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await']);

const PUNCT3 = ['===', '!==', '**=', '...', '>>>', '<<=', '>>=', '&&=', '||=',
    '??='];
const PUNCT2 = ['=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--',
    '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>'];

const SIMPLE_ESC = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v',
    '0': '\0' };

function cookEscape(src, i) {
    // src[i] === '\\'; возвращает [строка, новый индекс].
    const c = src[i + 1];
    if (c === undefined) return ['', i + 1];
    if (c === '\n') return ['', i + 2];
    if (c === '\r') return ['', src[i + 2] === '\n' ? i + 3 : i + 2];
    if (c in SIMPLE_ESC && !(c === '0' && /[0-9]/.test(src[i + 2] || ''))) {
        return [SIMPLE_ESC[c], i + 2];
    }
    if (c === 'x') {
        return [String.fromCharCode(parseInt(src.substr(i + 2, 2), 16)), i + 4];
    }
    if (c === 'u') {
        if (src[i + 2] === '{') {
            const end = src.indexOf('}', i + 3);
            return [String.fromCodePoint(parseInt(src.slice(i + 3, end), 16)),
                end + 1];
        }
        return [String.fromCharCode(parseInt(src.substr(i + 2, 4), 16)), i + 6];
    }
    return [c, i + 2];
}

function tokenize(src) {
    const toks = [];
    let i = 0;
    const n = src.length;
    let prev = null;          // последний значимый токен (для regex)

    function push(t) { toks.push(t); prev = t; }

    function regexAllowed() {
        if (!prev) return true;
        if (prev.type === 'punct') return REGEX_PREV.has(prev.value)
            && prev.value !== ')' && prev.value !== ']';
        if (prev.type === 'ident') return REGEX_PREV.has(prev.value);
        return false;
    }

    while (i < n) {
        const c = src[i];
        if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
        if (c === '/' && src[i + 1] === '/') {
            const e = src.indexOf('\n', i);
            i = e < 0 ? n : e;
            continue;
        }
        if (c === '/' && src[i + 1] === '*') {
            const e = src.indexOf('*/', i + 2);
            i = e < 0 ? n : e + 2;
            continue;
        }
        if (c === '"' || c === "'") {
            let j = i + 1;
            let val = '';
            while (j < n && src[j] !== c) {
                if (src[j] === '\\') {
                    const [s, k] = cookEscape(src, j);
                    val += s; j = k;
                } else { val += src[j]; j++; }
            }
            push({ type: 'str', value: val, start: i, end: j + 1 });
            i = j + 1;
            continue;
        }
        if (c === '`') {
            const t = readTemplate(src, i);
            push(t);
            i = t.end;
            continue;
        }
        if (c === '/' && regexAllowed()) {
            let j = i + 1;
            let inClass = false;
            while (j < n) {
                const d = src[j];
                if (d === '\\') { j += 2; continue; }
                if (d === '\n') break;
                if (inClass) { if (d === ']') inClass = false; }
                else if (d === '[') inClass = true;
                else if (d === '/') break;
                j++;
            }
            j++;
            while (j < n && /[a-z]/i.test(src[j])) j++;
            push({ type: 'regex', start: i, end: j });
            i = j;
            continue;
        }
        if (/[A-Za-z_$]/.test(c)) {
            let j = i + 1;
            while (j < n && /[\w$]/.test(src[j])) j++;
            push({ type: 'ident', value: src.slice(i, j), start: i, end: j });
            i = j;
            continue;
        }
        if (/[0-9]/.test(c)) {
            let j = i + 1;
            while (j < n && /[\w.]/.test(src[j])) j++;
            push({ type: 'num', start: i, end: j });
            i = j;
            continue;
        }
        let p = c;
        const three = src.substr(i, 3);
        const two = src.substr(i, 2);
        if (PUNCT3.includes(three)) p = three;
        else if (PUNCT2.includes(two)) p = two;
        push({ type: 'punct', value: p, start: i, end: i + p.length });
        i += p.length;
    }
    return toks;
}

// Шаблон `…${…}…`: quasis (готовые строки) и исходники выражений.
function readTemplate(src, i) {
    const quasis = [];
    const exprs = [];
    let j = i + 1;
    let cur = '';
    const n = src.length;
    while (j < n) {
        const d = src[j];
        if (d === '\\') {
            const [s, k] = cookEscape(src, j);
            cur += s; j = k; continue;
        }
        if (d === '`') { j++; break; }
        if (d === '$' && src[j + 1] === '{') {
            quasis.push(cur); cur = '';
            const start = j + 2;
            const end = skipExpr(src, start);
            exprs.push(src.slice(start, end));
            j = end + 1;
            continue;
        }
        cur += d; j++;
    }
    quasis.push(cur);
    return { type: 'tpl', quasis, exprs, start: i, end: j };
}

// Пропускает выражение внутри ${…} до парной «}». Регулярки (`/'/g`)
// пропускаются целиком, иначе кавычка внутри них сбила бы разбор.
function skipExpr(src, i) {
    let depth = 0;
    let last = '';            // последний значимый символ (для regex)
    const n = src.length;
    while (i < n) {
        const c = src[i];
        if (c === '"' || c === "'") {
            i++;
            while (i < n && src[i] !== c) { if (src[i] === '\\') i++; i++; }
            i++; last = c; continue;
        }
        if (c === '`') { i = readTemplate(src, i).end; last = c; continue; }
        if (c === '/' && src[i + 1] === '/') {
            const e = src.indexOf('\n', i); i = e < 0 ? n : e; continue;
        }
        if (c === '/' && src[i + 1] === '*') {
            const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue;
        }
        if (c === '/' && (last === '' || '(,=:[!&|?{};+-*%<>~^'.includes(last))) {
            let cls = false;
            i++;
            while (i < n && src[i] !== '\n') {
                const d = src[i];
                if (d === '\\') { i += 2; continue; }
                if (d === '[') cls = true;
                else if (d === ']') cls = false;
                else if (d === '/' && !cls) break;
                i++;
            }
            i++;
            while (i < n && /[a-z]/i.test(src[i])) i++;
            last = '/'; continue;
        }
        if (c === '{') depth++;
        else if (c === '}') { if (depth === 0) return i; depth--; }
        if (!/\s/.test(c)) last = c;
        i++;
    }
    return n;
}

// ── HTML-нормализация ──────────────────────────────────────────────

const ENTITIES = {
    nbsp: ' ', laquo: '«', raquo: '»', mdash: '—', ndash: '–', hellip: '…',
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", times: '×', middot: '·',
    rarr: '→', larr: '←', uarr: '↑', darr: '↓', bull: '•', copy: '©',
    deg: '°', le: '≤', ge: '≥', ne: '≠', thinsp: ' ', ensp: ' ', emsp: ' ',
    shy: '', zwnj: '', zwj: '', minus: '−', plusmn: '±', check: '✓',
};

function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, e) => {
        if (e[0] === '#') {
            const code = e[1] === 'x' || e[1] === 'X'
                ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
            return String.fromCodePoint(code);
        }
        const v = ENTITIES[e.toLowerCase()];
        return v === undefined ? m : v;
    });
}

// Нормализация, общая с рантаймом (i18n.js normalize): NBSP и прочие
// пробелы → пробел, схлопнуть, обрезать.
function normalize(s) {
    return s.replace(/[\s   ]+/g, ' ').trim();
}

// Маркеры подстановок внутри склеенной строки.
const PH = (k) => `\u0001${k}\u0002`;
const PH_RE = /\u0001(\d+)\u0002/g;

// Превращает кусок с маркерами в ключ: маркеры нумеруются заново с {0}.
function toKey(text) {
    let idx = 0;
    const map = new Map();
    let s = decodeEntities(text);
    s = s.replace(PH_RE, (m, k) => {
        if (!map.has(k)) map.set(k, idx++);
        return `{${map.get(k)}}`;
    });
    s = normalize(s);
    // Кусок, который целиком — подстановка с пунктуацией, ключом не бывает.
    if (!CYR.test(s)) return null;
    return s;
}

// Режет склеенную строку (с маркерами) на ключи: текст между тегами и
// значения «текстовых» атрибутов.
function splitHtml(str, out) {
    const tagRe = /<\/?[a-zA-Z!][^<>]*>/g;
    let last = 0;
    let m;
    const hasTags = tagRe.test(str);
    tagRe.lastIndex = 0;
    if (!hasTags) {
        // Без тегов: многострочный текст (confirm/alert, title-подсказки)
        // целиком — один ключ; переводчик для них не режет по строкам.
        const k = toKey(str);
        if (k) out.add(k);
        return;
    }
    while ((m = tagRe.exec(str))) {
        const k = toKey(str.slice(last, m.index));
        if (k) out.add(k);
        attrKeys(m[0], out);
        last = m.index + m[0].length;
    }
    const k = toKey(str.slice(last));
    if (k) out.add(k);
}

function attrKeys(tag, out) {
    const re = /([\w:-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let m;
    while ((m = re.exec(tag))) {
        const name = m[1].toLowerCase();
        const val = m[3] !== undefined ? m[3] : m[4];
        if (TEXT_ATTRS.includes(name)
            || (name === 'value' && BUTTON_INPUT.test(tag))) {
            const k = toKey(val);
            if (k) out.add(k);
        } else if (name.startsWith('on') && CYR.test(val)) {
            // onclick="…confirm('Удалить?')…": строки внутри обработчика.
            const sr = /'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"/g;
            let q;
            const dec = val.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            while ((q = sr.exec(dec))) {
                const k = toKey(q[1] !== undefined ? q[1] : q[2]);
                if (k) out.add(k);
            }
        }
    }
}

// ── Сборка «склеенных» строк из токенов ───────────────────────────

const STOP = new Set([',', ';', ')', ']', '}', ':', '?', '(', '[', '{', '=',
    '=>', '&&', '||', '??', '+=', '-=', 'return', '==', '===', '!=', '!==']);

function isLit(t) { return t && (t.type === 'str' || t.type === 'tpl'); }

// Индекс токена, где кончается операнд, начинающийся с i (вперёд).
function operandEnd(toks, i) {
    let depth = 0;
    let j = i;
    for (; j < toks.length; j++) {
        const t = toks[j];
        if (t.type === 'punct') {
            const v = t.value;
            if (v === '(' || v === '[' || v === '{') { depth++; continue; }
            if (v === ')' || v === ']' || v === '}') {
                if (depth === 0) return j;
                depth--; continue;
            }
            if (depth === 0 && (v === '+' || STOP.has(v))) return j;
        }
        if (depth === 0 && t.type === 'ident' && t.value === 'return') return j;
    }
    return j;
}

// Индекс первого токена операнда, который кончается на i (назад).
function operandStart(toks, i) {
    let depth = 0;
    let j = i;
    for (; j >= 0; j--) {
        const t = toks[j];
        if (t.type === 'punct') {
            const v = t.value;
            if (v === ')' || v === ']' || v === '}') { depth++; continue; }
            if (v === '(' || v === '[' || v === '{') {
                if (depth === 0) return j + 1;
                depth--; continue;
            }
            if (depth === 0 && (v === '+' || STOP.has(v))) return j + 1;
        }
        if (depth === 0 && t.type === 'ident'
            && (t.value === 'return' || t.value === 'case')) return j + 1;
    }
    return 0;
}

// Строка литерала с маркерами: шаблон склеивается с маркерами на месте
// выражений; сами выражения разбираются рекурсивно (там свои литералы).
function litString(t, counter, out, src) {
    if (t.type === 'str') return t.value;
    let s = t.quasis[0];
    for (let k = 0; k < t.exprs.length; k++) {
        extractFrom(t.exprs[k], out);
        s += PH(counter.n++) + t.quasis[k + 1];
    }
    return s;
}

function extractFrom(src, out) {
    if (!CYR.test(src)) return;
    let toks;
    try { toks = tokenize(src); } catch (e) { return; }
    const used = new Set();
    for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        if (!isLit(t) || used.has(i)) continue;
        // Начало цепочки: назад через «+» от литерала.
        let first = i;
        let head = null;     // операнд-не-литерал перед первой «+»
        if (toks[i - 1] && toks[i - 1].type === 'punct'
            && toks[i - 1].value === '+') {
            const st = operandStart(toks, i - 2);
            if (st <= i - 2) head = [st, i - 2];
        }
        // Вперёд: литерал (+ операнд)* …
        const parts = [];        // {lit: tok} | {expr: [a,b]}
        if (head) parts.push({ expr: head });
        parts.push({ lit: t });
        used.add(i);
        let j = i + 1;
        while (toks[j] && toks[j].type === 'punct' && toks[j].value === '+') {
            const a = j + 1;
            if (isLit(toks[a]) && !(toks[a + 1] && toks[a + 1].type === 'punct'
                && (toks[a + 1].value === '.' || toks[a + 1].value === '['))) {
                parts.push({ lit: toks[a] });
                used.add(a);
                j = a + 1;
                continue;
            }
            const e = operandEnd(toks, a);
            if (e === a) break;
            parts.push({ expr: [a, e - 1] });
            // Литералы внутри операнда (тернарники и т.п.) — своими ключами.
            for (let q = a; q < e; q++) {
                if (isLit(toks[q])) {
                    used.add(q);
                    const c2 = { n: 0 };
                    splitHtml(litString(toks[q], c2, out, src), out);
                }
            }
            j = e;
        }
        // Склейка.
        const counter = { n: 0 };
        let s = '';
        const litCount = parts.filter((p) => p.lit).length;
        for (const p of parts) {
            if (p.lit) s += litString(p.lit, counter, out, src);
            else s += PH(counter.n++);
        }
        splitHtml(s, out);
        // Литералы цепочки по отдельности — запасной вариант, когда
        // подстановка в DOM разрывает текст (например, вставляет тег).
        if (parts.length > litCount) {
            for (const p of parts) {
                if (!p.lit) continue;
                const c2 = { n: 0 };
                const one = new Set();
                splitHtml(litString(p.lit, c2, new Set(), src), one);
                for (const k of one) out.add(k);
            }
        }
        void first;
    }
}

// ── index.html ─────────────────────────────────────────────────────

function extractHtml(src, out) {
    const body = src.replace(/<!--[\s\S]*?-->/g, '')
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<style[\s\S]*?<\/style>/gi, '');
    splitHtml(body, out);
}

// ── Обход файлов ───────────────────────────────────────────────────

function listFiles() {
    const files = [];
    (function walk(dir) {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
            const p = path.join(dir, e.name);
            if (e.isDirectory()) walk(p);
            else if (/\.(js|html)$/.test(e.name)) files.push(p);
        }
    })(WEB);
    return files.sort();
}

function extractFile(file) {
    const rel = path.relative(WEB, file).split(path.sep).join('/');
    const out = new Set();
    if (SKIP_FILES.has(rel)) return { rel, keys: out };
    const src = fs.readFileSync(file, 'utf8');
    if (file.endsWith('.html')) extractHtml(src, out);
    else extractFrom(src, out);
    return { rel, keys: out };
}

function extractAll() {
    const all = new Map();
    for (const f of listFiles()) {
        const { rel, keys } = extractFile(f);
        for (const k of keys) {
            if (!all.has(k)) all.set(k, []);
            all.get(k).push(rel);
        }
    }
    return all;
}

function loadDict() {
    if (!fs.existsSync(DICT)) return {};
    const src = fs.readFileSync(DICT, 'utf8');
    const sandbox = {};
    // eslint-disable-next-line no-new-func
    new Function('globalThis', src + '\nglobalThis.d = i18n_en_text;')(sandbox);
    return sandbox.d;
}

function placeholders(s) {
    return (s.match(/\{\d+\}/g) || []).sort().join(',');
}

module.exports = { extractAll, extractFrom, tokenize, normalize, loadDict,
    placeholders, DICT };

if (require.main === module) {
    const arg = process.argv[2] || '--stats';
    const all = extractAll();
    const dict = loadDict();
    if (arg === '--stats') {
        const per = new Map();
        for (const [k, files] of all) {
            for (const f of files) per.set(f, (per.get(f) || 0) + 1);
        }
        const rows = [...per].sort((a, b) => b[1] - a[1]);
        for (const [f, c] of rows) console.log(String(c).padStart(5), f);
        let chars = 0;
        for (const k of all.keys()) chars += k.length;
        const miss = [...all.keys()].filter((k) => !dict[k]).length;
        console.log(`всего ключей: ${all.size}, символов: ${chars}, `
            + `без перевода: ${miss}`);
    } else if (arg === '--missing') {
        const file = process.argv[3];
        const miss = {};
        for (const [k, files] of all) {
            if (dict[k]) continue;
            if (file && !files.includes(file)) continue;
            miss[k] = '';
        }
        console.log(JSON.stringify(miss, null, 1));
    } else if (arg === '--unused') {
        for (const k of Object.keys(dict)) if (!all.has(k)) console.log(k);
    } else if (arg === '--check') {
        let bad = 0;
        for (const [k, files] of all) {
            if (!dict[k]) {
                bad++;
                if (bad <= 50) console.error(`нет перевода: ${JSON.stringify(k)} (${files[0]})`);
            }
        }
        for (const [k, v] of Object.entries(dict)) {
            if (placeholders(k) !== placeholders(v)) {
                bad++;
                console.error(`подстановки не совпадают: ${JSON.stringify(k)} → ${JSON.stringify(v)}`);
            }
        }
        if (bad) { console.error(`ошибок: ${bad}`); process.exit(1); }
        console.log(`ok: ${all.size} ключей`);
    }
}
