/**
 * i18n.js — язык интерфейса (русский по умолчанию, английский по выбору).
 *
 * Два механизма, оба работают в английском режиме:
 *
 * 1. Ключи: _t('mcp.warn.token') → строка из словаря i18n_ru / i18n_en
 *    (web/js/i18n/ru.js, en.js). Удобно для длинных текстов в новом коде.
 *
 * 2. Перевод готового DOM по словарю «русская фраза → английская»
 *    (web/js/i18n/en.text.js, собирается tools/i18n_extract.js). Интерфейс
 *    написан по-русски прямо в шаблонах страниц; переводчик проходит DOM
 *    при загрузке и следит за изменениями (MutationObserver): текстовые
 *    узлы, атрибуты title/placeholder/aria-label/alt, value у кнопок.
 *    Ключи с местами подстановки {0}, {1} сопоставляются как шаблоны,
 *    значения подстановок переводятся тем же словарём.
 *
 * В русском режиме словарь фраз не грузится и наблюдатель не ставится.
 * Выбор языка хранится в localStorage (как тема), см. docs/i18n.md.
 */
const i18n = (() => {
    const KEY = 'zapret-gui-lang';
    const LANGS = ['ru', 'en'];
    const CYR = /[А-Яа-яЁё]/;
    const TEXT_ATTRS = ['title', 'placeholder', 'aria-label', 'alt',
        'data-tip', 'data-label'];
    // Внутри этих элементов — данные пользователя и вывод программ.
    const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'PRE', 'CODE',
        'NOSCRIPT', 'TEMPLATE']);

    let currentLang = 'ru';
    try {
        const v = localStorage.getItem(KEY);
        if (LANGS.includes(v)) currentLang = v;
    } catch (_) { /* приватный режим: остаёмся на русском */ }

    // ── Ключевой API ───────────────────────────────────────────────

    function getTranslations() {
        if (currentLang === 'en') {
            return typeof i18n_en !== 'undefined' ? i18n_en : {};
        }
        return typeof i18n_ru !== 'undefined' ? i18n_ru : {};
    }

    function translate(key, variables = {}) {
        const translations = getTranslations();
        let text = translations[key];
        if (text === undefined) {
            text = currentLang === 'en' ? translateText(String(key)) : key;
        }
        for (const [varName, varVal] of Object.entries(variables)) {
            text = text.split(`{${varName}}`).join(varVal);
        }
        return text;
    }

    function getLanguage() {
        return currentLang;
    }

    // Страница с несохранёнными правками может отказать в перезагрузке.
    let switchGuard = null;
    function setSwitchGuard(fn) {
        switchGuard = typeof fn === 'function' ? fn : null;
    }

    // Видимые метки «не сохранено» редакторов (lua, hostlist, ipset,
    // hosts, маршруты) — им отдельный страж не нужен.
    function visibleUnsaved() {
        if (typeof document === 'undefined' || !document.querySelectorAll) {
            return false;
        }
        return [...document.querySelectorAll('.lists-unsaved, #ru-dirty')]
            .some((e) => e.offsetParent !== null);
    }

    /** Сменить язык (перезагрузка страницы). false — смена не состоялась. */
    function setLanguage(lang) {
        if (!LANGS.includes(lang) || lang === currentLang) return false;
        if (switchGuard && !switchGuard()) return false;
        if (!switchGuard && visibleUnsaved()
            && !confirm('Есть несохранённые изменения. Сменить язык и потерять их?')) {
            return false;
        }
        try {
            localStorage.setItem(KEY, lang);
            if (localStorage.getItem(KEY) !== lang) throw new Error('storage');
        } catch (_) {
            // Без localStorage выбор не переживёт перезагрузку.
            if (typeof alert === 'function') {
                alert('Браузер не даёт сохранить выбор языка (приватный '
                    + 'режим или запрет хранения данных сайта).');
            }
            return false;
        }
        currentLang = lang;
        if (typeof location !== 'undefined') location.reload();
        return true;
    }

    // Локаль для toLocaleString / Intl.
    function locale() {
        return currentLang === 'en' ? 'en-US' : 'ru-RU';
    }

    // ── Словарь фраз ───────────────────────────────────────────────

    const LONG = 600;      // длиннее — без шаблонов и кусков
    const memo = new Map(); // кэш translateText: исходный текст → итог
    let exact = null;      // Map: нормализованная фраза → перевод
    let buckets = null;    // Map: первое русское слово → [шаблоны]

    function normalize(s) {
        return s.replace(/[\s   ]+/g, ' ').trim();
    }

    function escapeRe(s) {
        return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function buildIndex(dict) {
        memo.clear();
        exact = new Map();
        buckets = new Map();
        for (const [k, v] of Object.entries(dict || {})) {
            if (typeof v !== 'string' || v === '') continue;
            if (!/\{\d+\}/.test(k)) { exact.set(k, v); continue; }
            const parts = k.split(/(\{\d+\})/);
            const isPh = (p) => /^\{\d+\}$/.test(p);
            let re = '^';
            const order = [];
            let staticLen = 0;
            parts.forEach((p, i) => {
                const m = /^\{(\d+)\}$/.exec(p);
                if (m) { re += '(.*?)'; order.push(+m[1]); return; }
                if (p === '') return;
                // Пробел между подстановками исчезает, только когда
                // хвост пуст (обрезанный узел DOM), а не внутри слова.
                if (p.trim() === '') { re += '(?:\\s+|$)'; return; }
                staticLen += p.trim().length;
                // Узел DOM приходит обрезанным: пробел между текстом и
                // подстановкой на краю строки может отсутствовать.
                const onlyPhBefore = parts.slice(0, i).every(
                    (q) => q === '' || isPh(q));
                const onlyPhAfter = parts.slice(i + 1).every(
                    (q) => q === '' || isPh(q));
                let body = p;
                let pre = '';
                let post = '';
                if (onlyPhBefore && i > 0 && /^\s/.test(body)) {
                    body = body.replace(/^\s+/, ''); pre = '(?:^|\\s+)';
                }
                if (onlyPhAfter && i < parts.length - 1 && /\s$/.test(body)) {
                    body = body.replace(/\s+$/, ''); post = '(?:\\s+|$)';
                }
                re += pre + escapeRe(body) + post;
            });
            const word = (k.match(/[А-Яа-яЁё]+/) || [''])[0];
            const cyrLen = k.replace(/\{\d+\}/g, '')
                .replace(/[^А-Яа-яЁё]/g, '').length;
            const pat = { re: new RegExp(re + '$', 's'), order, to: v,
                staticLen, cyrLen };
            if (!buckets.has(word)) buckets.set(word, []);
            buckets.get(word).push(pat);
        }
        for (const list of buckets.values()) {
            list.sort((a, b) => b.staticLen - a.staticLen);
        }
    }

    function ensureIndex() {
        if (exact) return;
        buildIndex(typeof i18n_en_text !== 'undefined' ? i18n_en_text : {});
    }

    // Перевод одной фразы (без ведущих/хвостовых пробелов). null — не знаем.
    // Шаблон, после которого в строке осталась кириллица (подстановка не
    // перевелась), считается частичным: ищем полный, частичный — запасной.
    function lookup(s, depth) {
        const hit = exactCI(s);
        if (hit !== null) return hit;
        if (depth > 2) return null;
        const words = s.match(/[А-Яа-яЁё]+/g);
        if (!words) return null;
        const seen = new Set();
        let partial = null;
        for (const w of words) {
            if (seen.has(w)) continue;
            seen.add(w);
            const list = buckets.get(w);
            if (!list) continue;
            for (const p of list) {
                const m = p.re.exec(s);
                if (!m) continue;
                let out = p.to;
                let full = true;
                for (let i = 0; i < p.order.length; i++) {
                    let val = m[i + 1];
                    if (CYR.test(val)) {
                        const t = translateText(val, depth + 1);
                        if (t !== null) val = t; else full = false;
                    }
                    out = out.split(`{${p.order[i]}}`).join(val);
                }
                out = out.replace(/ {2,}/g, ' ').trim();
                if (full) return out;
                // Частичный перевод годится, только если переведённая
                // часть хотя бы вдвое длиннее оставшейся русской (метка +
                // данные), иначе выйдет каша вроде «Profile только для …».
                const rest = (out.match(/[А-Яа-яЁё]/g) || []).length;
                if (partial === null && depth === 0
                    && p.cyrLen >= 2 * rest) {
                    partial = out;
                }
            }
        }
        // Перевод по кускам полный, поэтому он лучше частичного.
        const pieces = bySegments(s, depth);
        return pieces !== null ? pieces : partial;
    }

    // Запасной путь: строка, склеенная из известных кусков через
    // разделители («Раздел · Подраздел», «Метка: значение», «текст:»).
    // Переводится, только если перевелись все куски с кириллицей.
    const SEP = /(\s+[·—–|+×]\s+|[:,;]\s+|\.\s+(?=[А-ЯЁA-Z])|^[·—–+•(]\s*|[:.)]$|\s*\(|\)\s*)/;
    function bySegments(s, depth) {
        // Сначала — только маркер в начале («— текст», «· текст»).
        const pm = /^([·—–+•]\s*)(.+)$/.exec(s);
        if (pm) {
            const t = lookupNested(pm[2], depth);
            if (t !== null) return pm[1] + t;
        }
        const segs = s.split(SEP);
        if (segs.length < 2) return null;
        const tr = (core) => (core === s ? exactCI(core)
            : lookupNested(core, depth));
        let changed = false;
        for (let i = 0; i < segs.length; i += 2) {
            const seg = segs[i];
            if (!CYR.test(seg)) continue;
            const core = seg.trim();
            let t = tr(core);
            if (t !== null) {
                segs[i] = seg.replace(core, () => t);
            } else {
                // Кусок вместе с разделителями: «(открывалось {0} из {1})»,
                // «Текущее состояние совпадает.».
                const before = i > 0 ? segs[i - 1] : '';
                const after = i + 1 < segs.length ? segs[i + 1] : '';
                let used = null;
                for (const [b, a] of [['', after], [before, ''],
                    [before, after]]) {
                    if (!a && !b) continue;
                    const raw = b + seg + a;
                    t = tr(raw.trim());
                    if (t !== null) { used = [b, a, raw]; break; }
                }
                if (used === null) return null;
                const [b, a, raw] = used;
                if (b) segs[i - 1] = '';
                if (a) segs[i + 1] = '';
                segs[i] = raw.match(/^\s*/)[0] + t + raw.match(/\s*$/)[0];
            }
            changed = true;
        }
        return changed ? segs.join('') : null;
    }

    // Точное совпадение; «не установлен» найдёт и «Не установлен».
    function exactCI(s) {
        const hit = exact.get(s);
        if (hit !== undefined) return hit;
        const c = s.charAt(0);
        const up = c.toUpperCase();
        if (c === up) return null;
        const alt = exact.get(up + s.slice(1));
        if (alt === undefined) return null;
        if (/^.[A-Z]/.test(alt)) return alt;
        return alt.charAt(0).toLowerCase() + alt.slice(1);
    }

    function lookupNested(core, depth) {
        const t = lookup(core, depth + 1);
        return t !== null && !CYR.test(t) ? t : null;
    }

    /**
     * Перевод строки на английский. Пробелы по краям сохраняются; если
     * перевода нет — строка возвращается как есть (или null при depth).
     */
    function translateText(text, depth) {
        const top = depth === undefined;
        if (typeof text !== 'string' || !CYR.test(text)) {
            return top ? text : null;
        }
        if (top && currentLang !== 'en') return text;
        ensureIndex();
        if (top) {
            // Страницы перерисовываются целиком, фразы повторяются: кэш.
            const hit = memo.get(text);
            if (hit !== undefined) return hit;
            const res = translateUncached(text);
            if (memo.size >= 5000) memo.clear();
            memo.set(text, res);
            return res;
        }
        return translateUncached(text, depth);
    }

    function translateUncached(text, depth) {
        const top = depth === undefined;
        const lead = text.match(/^[\s ]*/)[0];
        const trail = text.slice(lead.length).match(/[\s ]*$/)[0];
        const core = normalize(text);
        // Длинный текст (вывод программ, большие ошибки) — только точное
        // совпадение и по строкам: шаблоны на нём слишком дороги.
        const out = core.length > LONG ? exactCI(core)
            : lookup(core, top ? 0 : depth);
        if (out === null) {
            // Многострочный текст (confirm, подсказки): по строкам.
            if (/\n/.test(text.trim())) {
                const lines = text.split('\n');
                let changed = false;
                const tr = lines.map((ln) => {
                    if (!CYR.test(ln)) return ln;
                    const t = translateText(ln, top ? 0 : depth);
                    if (t !== null && t !== ln) changed = true;
                    return t === null ? ln : t;
                });
                if (changed) return tr.join('\n');
            }
            if (top) {
                noteMissing(core);
                return text;
            }
            return null;
        }
        return lead + out + trail;
    }

    // Недостающие фразы — для отладки: i18n.missing() в консоли.
    const missingSet = new Set();
    function noteMissing(s) {
        if (missingSet.size < 2000) missingSet.add(s);
    }

    // ── Обход DOM ──────────────────────────────────────────────────

    function skipped(el) {
        for (let e = el; e && e.nodeType === 1; e = e.parentNode) {
            if (SKIP_TAGS.has(e.tagName)) return true;
            if (e.isContentEditable) return true;
            if (e.getAttribute('translate') === 'no') return true;
            if (e.hasAttribute('data-no-i18n')) return true;
        }
        return false;
    }

    function translateTextNode(node) {
        const v = node.nodeValue;
        if (!v || !CYR.test(v)) return;
        if (skipped(node.parentNode)) return;
        const t = translateText(v);
        if (t !== v) node.nodeValue = t;
    }

    function translateAttrs(el) {
        for (const a of TEXT_ATTRS) {
            const v = el.getAttribute(a);
            if (v && CYR.test(v)) {
                const t = translateText(v);
                if (t !== v) el.setAttribute(a, t);
            }
        }
        if (el.tagName === 'INPUT' && /^(button|submit|reset)$/i.test(el.type)) {
            const v = el.value;
            if (v && CYR.test(v)) {
                // Запись value у кнопки меняет атрибут → снова наблюдатель:
                // писать только когда перевод другой, иначе цикл.
                const t = translateText(v);
                if (t !== v) el.value = t;
            }
        }
        if (el.tagName === 'OPTGROUP') {
            const v = el.getAttribute('label');
            if (v && CYR.test(v)) {
                const t = translateText(v);
                if (t !== v) el.setAttribute('label', t);
            }
        }
    }

    function translateTree(root) {
        if (!root) return;
        if (root.nodeType === 3) { translateTextNode(root); return; }
        if (root.nodeType !== 1 && root.nodeType !== 9
            && root.nodeType !== 11) return;
        if (root.nodeType === 1) {
            if (skipped(root)) return;
            translateAttrs(root);
        }
        const doc = root.ownerDocument || root;
        const walker = doc.createTreeWalker(root, 1 | 4, {
            acceptNode(n) {
                if (n.nodeType === 1) {
                    if (SKIP_TAGS.has(n.tagName) || n.isContentEditable
                        || n.getAttribute('translate') === 'no'
                        || n.hasAttribute('data-no-i18n')) return 2; // REJECT
                    return 1;
                }
                return CYR.test(n.nodeValue) ? 1 : 3;          // SKIP
            },
        });
        let n;
        while ((n = walker.nextNode())) {
            if (n.nodeType === 3) {
                const t = translateText(n.nodeValue);
                if (t !== n.nodeValue) n.nodeValue = t;
            } else {
                translateAttrs(n);
            }
        }
    }

    let observer = null;

    function observe() {
        if (observer || typeof MutationObserver === 'undefined') return;
        observer = new MutationObserver((records) => {
            for (const r of records) {
                if (r.type === 'childList') {
                    for (const n of r.addedNodes) translateTree(n);
                } else if (r.type === 'characterData') {
                    translateTextNode(r.target);
                } else if (r.type === 'attributes') {
                    const v = r.target.getAttribute(r.attributeName);
                    if (v && CYR.test(v) && !skipped(r.target)) {
                        translateAttrs(r.target);
                    }
                }
            }
        });
        observer.observe(document.documentElement, {
            childList: true, subtree: true, characterData: true,
            attributes: true, attributeFilter: TEXT_ATTRS.concat(['value']),
        });
    }

    // Нативные диалоги: текст в них не попадает в DOM.
    function wrapDialogs() {
        if (typeof window === 'undefined') return;
        for (const name of ['alert', 'confirm', 'prompt']) {
            const orig = window[name];
            if (typeof orig !== 'function') continue;
            window[name] = function (msg, ...rest) {
                if (arguments.length === 0) return orig.call(window);
                return orig.call(window, translateText(String(msg)), ...rest);
            };
        }
    }

    // Кнопка в подвале меню показывает язык, на который переключит.
    function syncToggle() {
        const btn = document.getElementById('lang-toggle');
        if (!btn) return;
        const toEn = currentLang !== 'en';
        btn.textContent = toEn ? 'EN' : 'RU';
        btn.title = toEn ? 'English' : 'Русский';
        btn.setAttribute('aria-label',
            toEn ? 'Switch to English' : 'Переключить на русский');
    }

    function start() {
        // Без настоящего DOM (тесты в node:vm) — только API перевода.
        if (typeof document === 'undefined' || !document.documentElement) {
            return;
        }
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', syncToggle);
        } else {
            syncToggle();
        }
        if (currentLang !== 'en') return;
        document.documentElement.setAttribute('lang', 'en');
        wrapDialogs();
        const run = () => {
            translateTree(document.body);
            const t = translateText(document.title);
            if (t !== document.title) document.title = t;
            observe();
        };
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', run);
        } else {
            run();
        }
    }

    // Словарь фраз грузим только для английского, синхронно и до скриптов
    // страниц (document.write из внешнего скрипта во время разбора
    // документа вставляет <script> сразу следом — CSP 'self' это разрешает).
    if (currentLang === 'en' && typeof document !== 'undefined'
        && document.readyState === 'loading'
        && typeof i18n_en_text === 'undefined'
        && typeof document.write === 'function') {
        // Адрес — из <link> в index.html: там сервер проставил ?v=.
        const link = document.querySelector
            && document.querySelector('link[rel="x-i18n-en-text"]');
        const src = (link && link.getAttribute('href'))
            || '/js/i18n/en.text.js';
        document.write('<script src="' + src.replace(/"/g, '')
            + '"><\/script>');
    }
    start();

    return {
        t: translate,
        getLanguage,
        setLanguage,
        setSwitchGuard,
        locale,
        translateText,
        translateTree,
        missing: () => [...missingSet],
        // Для тестов: подставить словарь фраз без загрузки файла.
        _setTextDict(dict) { buildIndex(dict); },
    };
})();

// Глобальная функция для удобства
const _t = i18n.t;
