/**
 * autocomplete.js — Автодополнение параметров стратегий nfqws2 (ТОЛЬКО nfqws2).
 *
 * Контекстный popup при вводе в textarea профиля. Источник синтаксиса —
 * Nfqws2Spec; реальные файлы (blobs/hostlists/ipsets) подтягиваются с сервера.
 *
 * Триггеры: ввод символов, «=» (значение флага/субпараметра), «:» (звено
 * lua-цепочки) и Ctrl+Space (ручной вызов в любом месте).
 *
 * Предлагает:
 *   - имена флагов (--filter-tcp, --payload, --lua-desync, …) с описанием;
 *   - имена desync-функций (fake, multisplit, circular, …) + файл-источник;
 *   - субпараметры функции (blob, pos, tcp_md5, …) из её спецификации;
 *   - значения: payload/l7/pos/tls_mod/enum, детекторы/хосткеи circular;
 *   - файлы: blob (по имени), hostlist/ipset (по пути) — что есть в наличии.
 *
 * API:
 *   NfqwsAutocomplete.attach(textarea) / detach(textarea) / detachAll()
 *   NfqwsAutocomplete.loadFiles()           — подтянуть списки файлов
 *   NfqwsAutocomplete.refreshFiles()        — принудительно (сброс кеша)
 */

const NfqwsAutocomplete = (() => {

    const Spec = (typeof Nfqws2Spec !== 'undefined') ? Nfqws2Spec : null;

    // ══════════════════ Состояние ══════════════════

    const instances = new Map();
    let popup = null;
    let mirror = null;
    let activeInstance = null;

    let fileCache = { blobs: null, hostlists: null, ipsets: null, ts: 0 };
    const FILE_CACHE_TTL = 60000;

    // Иконки категорий для popup
    const KIND_ICON = {
        flag: '⚑', func: '⚙', subarg: '◦', value: '•', file: '📄',
        detector: '🔎', hostkey: '🔑', iff: '❓',
    };

    // ══════════════════ Popup / mirror ══════════════════

    function ensurePopup() {
        if (popup) return popup;
        popup = document.createElement('div');
        popup.className = 'nfq-ac-popup';
        popup.style.display = 'none';
        popup.setAttribute('role', 'listbox');
        popup.innerHTML = '<div class="nfq-ac-list"></div>';
        document.body.appendChild(popup);
        popup.addEventListener('mousedown', (e) => {
            e.preventDefault();
            const item = e.target.closest('.nfq-ac-item');
            if (item && activeInstance) insertSuggestion(activeInstance, parseInt(item.dataset.index, 10));
        });
        return popup;
    }

    function ensureMirror() {
        if (mirror) return mirror;
        mirror = document.createElement('div');
        mirror.className = 'nfq-ac-mirror';
        mirror.setAttribute('aria-hidden', 'true');
        document.body.appendChild(mirror);
        return mirror;
    }

    // ══════════════════ Attach / Detach ══════════════════

    function attach(textarea) {
        if (!textarea || instances.has(textarea)) return;
        const inst = { textarea, suggestions: [], selectedIndex: -1, visible: false };
        inst._onInput = () => handleInput(inst);
        inst._onKeyDown = (e) => handleKeyDown(inst, e);
        inst._onBlur = () => { setTimeout(() => hidePopup(inst), 150); };
        inst._onScroll = () => { if (inst.visible) positionPopup(inst); };
        textarea.addEventListener('input', inst._onInput);
        textarea.addEventListener('keydown', inst._onKeyDown);
        textarea.addEventListener('blur', inst._onBlur);
        textarea.addEventListener('scroll', inst._onScroll);
        textarea.setAttribute('autocomplete', 'off');
        textarea.setAttribute('spellcheck', 'false');
        instances.set(textarea, inst);
    }

    function detach(textarea) {
        const inst = instances.get(textarea);
        if (!inst) return;
        textarea.removeEventListener('input', inst._onInput);
        textarea.removeEventListener('keydown', inst._onKeyDown);
        textarea.removeEventListener('blur', inst._onBlur);
        textarea.removeEventListener('scroll', inst._onScroll);
        if (activeInstance === inst) { hidePopup(inst); activeInstance = null; }
        instances.delete(textarea);
    }

    function detachAll() {
        for (const [textarea] of instances) detach(textarea);
        if (popup) popup.style.display = 'none';
    }

    // ══════════════════ Ввод ══════════════════

    function handleInput(inst) {
        const ctx = getContext(inst.textarea);
        if (!ctx) { hidePopup(inst); return; }
        const suggestions = buildSuggestions(ctx);
        if (!suggestions.length) { hidePopup(inst); return; }
        inst.suggestions = suggestions;
        inst.selectedIndex = 0;
        showPopup(inst);
    }

    function handleKeyDown(inst, e) {
        if (e.key === ' ' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            const ctx = getContext(inst.textarea) || { type: 'flag', prefix: '' };
            const suggestions = buildSuggestions(ctx);
            if (suggestions.length) {
                inst.suggestions = suggestions;
                inst.selectedIndex = 0;
                showPopup(inst);
            }
            return;
        }
        if (!inst.visible) return;
        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                inst.selectedIndex = (inst.selectedIndex + 1) % inst.suggestions.length;
                renderItems(inst); scrollToSelected(inst); break;
            case 'ArrowUp':
                e.preventDefault();
                inst.selectedIndex = (inst.selectedIndex - 1 + inst.suggestions.length) % inst.suggestions.length;
                renderItems(inst); scrollToSelected(inst); break;
            case 'Enter':
            case 'Tab':
                if (inst.selectedIndex >= 0 && inst.selectedIndex < inst.suggestions.length) {
                    e.preventDefault();
                    insertSuggestion(inst, inst.selectedIndex);
                }
                break;
            case 'Escape':
                e.preventDefault(); e.stopPropagation(); hidePopup(inst); break;
        }
    }

    // ══════════════════ Контекст (nfqws2) ══════════════════

    function getContext(textarea) {
        if (!Spec) return null;
        const text = textarea.value;
        const cursorPos = textarea.selectionStart;
        const before = text.substring(0, cursorPos);
        const tokenStart = Math.max(before.lastIndexOf(' '), before.lastIndexOf('\n')) + 1;
        const currentToken = before.substring(tokenStart);

        if (currentToken.startsWith('--')) {
            const eqIdx = currentToken.indexOf('=');
            if (eqIdx < 0) return { type: 'flag', prefix: currentToken, tokenStart };
            const flag = currentToken.substring(0, eqIdx);
            const valueStr = currentToken.substring(eqIdx + 1);
            const valueStart = tokenStart + eqIdx + 1;
            return getValueContext(flag, valueStr, valueStart);
        }
        // пусто/после пробела/начало флага → подсказать флаги
        if (currentToken === '' || currentToken.startsWith('-')) {
            return { type: 'flag', prefix: currentToken, tokenStart };
        }
        return null;
    }

    function getValueContext(flag, valueStr, valueStart) {
        if (flag === '--lua-desync') return parseLuaChainContext(valueStr, valueStart);

        const fspec = Spec.flag(flag);
        if (!fspec || !fspec.arg) return null;
        const type = fspec.arg.type;

        if (flag === '--hostlist' || flag === '--hostlist-exclude' || flag === '--hostlist-auto')
            return { type: 'file', fileType: 'hostlist', prefix: valueStr, tokenStart: valueStart };
        if (flag === '--ipset' || flag === '--ipset-exclude')
            return { type: 'file', fileType: 'ipset', prefix: valueStr, tokenStart: valueStart };

        if (type === 'csv-enum')
            return parseCsv(valueStr, valueStart, fspec.arg.values, flag);
        if (type === 'enum')
            return { type: 'value', prefix: valueStr, tokenStart: valueStart, values: fspec.arg.values, label: flag };
        // числа/строки/порты/диапазоны — подскажем примеры, если есть
        if (fspec.arg.ex && fspec.arg.ex.length)
            return { type: 'value', prefix: valueStr, tokenStart: valueStart, values: fspec.arg.ex, label: flag };
        return null;
    }

    function parseLuaChainContext(valueStr, valueStart) {
        const colon = valueStr.lastIndexOf(':');
        const fnName = valueStr.split(':')[0];

        if (colon < 0) {
            // набираем имя функции
            return { type: 'func', prefix: valueStr, tokenStart: valueStart };
        }
        const lastPart = valueStr.substring(colon + 1);
        const lastStart = valueStart + colon + 1;
        const eq = lastPart.indexOf('=');

        if (eq < 0) {
            // имя субпараметра
            const already = valueStr.substring(0, colon).split(':').slice(1)
                .map(p => (p.indexOf('=') >= 0 ? p.split('=')[0] : p));
            return { type: 'subarg', fn: fnName, prefix: lastPart, tokenStart: lastStart, already };
        }
        // значение субпараметра
        const subkey = lastPart.substring(0, eq);
        const subval = lastPart.substring(eq + 1);
        const subStart = lastStart + eq + 1;
        const allowed = Spec.subargsFor(fnName);
        const sub = allowed[subkey];

        // blob/паттерны → файлы блобов
        if (subkey === 'blob' || subkey === 'seqovl_pattern' || subkey === 'pattern')
            return { type: 'file', fileType: 'blob', prefix: subval, tokenStart: subStart, isLuaBlob: true };

        if (sub) {
            if (sub.type === 'pos')
                return parseCsv(subval, subStart, posValues(), subkey, true);
            if (sub.type === 'tls_mod')
                return parseCsv(subval, subStart, Spec.TLS_MODS, subkey, true);
            if (sub.type === 'enum')
                return { type: 'value', prefix: subval, tokenStart: subStart, values: sub.values, label: subkey };
            const luaVals = Spec.valuesForSubargType(sub.type);
            if (luaVals)
                return { type: 'value', prefix: subval, tokenStart: subStart, values: luaVals, label: subkey,
                    iconKind: sub.type === 'lua-hostkey' ? 'hostkey' : (sub.type === 'lua-iff' ? 'iff' : 'detector') };
            if (sub.ex && sub.ex.length)
                return { type: 'value', prefix: subval, tokenStart: subStart, values: sub.ex, label: subkey };
        }
        return null;
    }

    function posValues() {
        // числа + относительные маркеры (с типовой арифметикой)
        return ['1', '2', 'midsld', 'host', 'endhost', 'sld', 'endsld', 'sniext',
            'method+2', 'sld+1', 'endhost-2', '-1'];
    }

    function parseCsv(valueStr, valueStart, values, label, isSub) {
        const comma = valueStr.lastIndexOf(',');
        const lastItem = comma < 0 ? valueStr : valueStr.substring(comma + 1);
        const lastStart = comma < 0 ? valueStart : valueStart + comma + 1;
        const already = comma < 0 ? [] : valueStr.substring(0, comma).split(',');
        return { type: 'value', prefix: lastItem, tokenStart: lastStart, values, label, already, isSub };
    }

    // ══════════════════ Построение подсказок ══════════════════

    function buildSuggestions(ctx) {
        switch (ctx.type) {
            case 'flag':    return buildFlagSuggestions(ctx.prefix);
            case 'func':    return buildFuncSuggestions(ctx.prefix);
            case 'subarg':  return buildSubargSuggestions(ctx.fn, ctx.prefix, ctx.already);
            case 'value':   return buildValueSuggestions(ctx);
            case 'file':    return buildFileSuggestions(ctx.fileType, ctx.prefix, ctx.isLuaBlob);
            default:        return [];
        }
    }

    function buildFlagSuggestions(prefix) {
        const p = (prefix || '').toLowerCase();
        const out = [];
        for (const name of Spec.allFlagNames()) {
            if (p && name.toLowerCase().indexOf(p) !== 0) continue;
            const f = Spec.flag(name);
            const needsEq = f.arg && !f.arg.optional && f.arg.type !== undefined;
            out.push({
                text: name,
                insert: name + (f.arg ? '=' : ' '),
                desc: f.desc, icon: KIND_ICON.flag, kind: 'flag',
                reopen: !!f.arg,
            });
            void needsEq;
        }
        return out.slice(0, 50);
    }

    function buildFuncSuggestions(prefix) {
        const p = (prefix || '').toLowerCase();
        const out = [];
        for (const name of Spec.allFuncNames()) {
            if (p && name.toLowerCase().indexOf(p) !== 0) continue;
            const fn = Spec.func(name);
            out.push({
                text: name, insert: name,
                desc: (fn.cat === 'orch' ? '⟳ ' : '') + (fn.desc || '') + ' · ' + fn.file,
                icon: KIND_ICON.func, kind: 'func',
            });
        }
        // core/orch выше расширений
        const rank = (n) => { const c = Spec.func(n).cat; return c === 'core' ? 0 : c === 'orch' ? 1 : 2; };
        out.sort((a, b) => rank(a.text) - rank(b.text) || a.text.localeCompare(b.text));
        return out.slice(0, 50);
    }

    function buildSubargSuggestions(fnName, prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(x => x.toLowerCase()));
        const allowed = Spec.subargsFor(fnName);
        const out = [];
        for (const [key, info] of Object.entries(allowed)) {
            if (skip.has(key.toLowerCase())) continue;
            if (p && key.toLowerCase().indexOf(p) !== 0) continue;
            const hasVal = info.type !== 'flag';
            out.push({
                text: key,
                insert: key + (hasVal ? '=' : ''),
                desc: (info.desc || '') + (info.kind && info.kind !== 'arg' ? ' [' + info.kind + ']' : ''),
                icon: KIND_ICON.subarg, kind: 'subarg', reopen: hasVal,
            });
        }
        // собственные args функции выше опций групп
        const ownRank = (k) => (allowed[k] && allowed[k].kind === 'arg') ? 0 : 1;
        out.sort((a, b) => ownRank(a.text) - ownRank(b.text) || a.text.localeCompare(b.text));
        return out.slice(0, 40);
    }

    function buildValueSuggestions(ctx) {
        const p = (ctx.prefix || '').toLowerCase();
        const skip = new Set((ctx.already || []).map(x => x.toLowerCase()));
        const icon = KIND_ICON[ctx.iconKind] || KIND_ICON.value;
        return (ctx.values || [])
            .filter(v => !skip.has(String(v).toLowerCase()) && (!p || String(v).toLowerCase().indexOf(p) === 0))
            .map(v => ({ text: String(v), insert: String(v), desc: ctx.label || '', icon, kind: 'value' }))
            .slice(0, 40);
    }

    function buildFileSuggestions(fileType, prefix, isLuaBlob) {
        const p = (prefix || '').toLowerCase();
        const out = [];
        if (fileType === 'blob') {
            // встроенные блобы nfqws2 (не требуют --blob)
            for (const name of ['fake_default_tls', 'fake_default_http', 'fake_default_quic']) {
                if (!p || name.toLowerCase().indexOf(p) === 0)
                    out.push({ text: name, insert: name, desc: 'Встроенный блоб', icon: KIND_ICON.file, kind: 'file' });
            }
        }
        const files = fileCache[fileType];
        if (files) {
            for (const f of files) {
                const name = f.name || f;
                if (p && name.toLowerCase().indexOf(p) !== 0) continue;
                if (out.find(r => r.text === name)) continue;
                const insert = (fileType === 'blob') ? name : (f.path || name);
                out.push({
                    text: name, insert,
                    desc: fileType === 'blob' ? 'Блоб' : fileType === 'hostlist' ? 'Список хостов' : 'IP-список',
                    icon: KIND_ICON.file, kind: 'file',
                });
            }
        }
        return out.slice(0, 30);
    }

    // ══════════════════ Файлы с сервера ══════════════════

    function loadFiles() {
        if (Date.now() - fileCache.ts < FILE_CACHE_TTL) return;
        _fetchFiles();
    }
    function refreshFiles() { fileCache.ts = 0; _fetchFiles(); }

    function _fetchFiles() {
        fileCache.ts = Date.now();
        const grab = (url, fn) => fetch(url).then(r => r.ok ? r.json() : null).then(fn).catch(() => {});
        grab('/api/blobs', d => { if (d) fileCache.blobs = (d.blobs || []).map(b => ({ name: b.name || b })); });
        grab('/api/hostlists', d => { if (d) fileCache.hostlists = (d.files || d.hostlists || []).map(h => ({ name: h.filename || h.name || h, path: h.path || h.name || h })); });
        grab('/api/ipsets', d => { if (d) fileCache.ipsets = (d.files || d.ipsets || []).map(i => ({ name: i.filename || i.name || i, path: i.path || i.name || i })); });
    }

    // ══════════════════ Вставка ══════════════════

    function insertSuggestion(inst, index) {
        const sug = inst.suggestions[index];
        if (!sug) return;
        const ta = inst.textarea;
        const text = ta.value;
        const cursorPos = ta.selectionStart;
        const ctx = getContext(ta);
        if (!ctx) { hidePopup(inst); return; }

        const replaceStart = ctx.tokenStart;
        const replaceEnd = cursorPos;
        const insertText = sug.insert;
        const before = text.substring(0, replaceStart);
        const after = text.substring(replaceEnd);

        ta.value = before + insertText + after;
        const newPos = replaceStart + insertText.length;
        ta.selectionStart = ta.selectionEnd = newPos;
        ta.dispatchEvent(new Event('input', { bubbles: true }));
        ta.dispatchEvent(new Event('change', { bubbles: true }));

        ta.focus();
        // Если вставили флаг/субпараметр с '=' — сразу переоткрыть popup со значениями.
        if (sug.reopen) {
            const ctx2 = getContext(ta);
            const next = ctx2 ? buildSuggestions(ctx2) : [];
            if (next.length) { inst.suggestions = next; inst.selectedIndex = 0; showPopup(inst); return; }
        }
        hidePopup(inst);
    }

    // ══════════════════ Popup show/hide/position ══════════════════

    function showPopup(inst) {
        ensurePopup();
        inst.visible = true;
        activeInstance = inst;
        renderItems(inst);
        positionPopup(inst);
        popup.style.display = 'block';
        scrollToSelected(inst);
    }

    function hidePopup(inst) {
        inst.visible = false;
        inst.suggestions = [];
        inst.selectedIndex = -1;
        if (popup) popup.style.display = 'none';
        if (activeInstance === inst) activeInstance = null;
    }

    function renderItems(inst) {
        if (!popup) return;
        const list = popup.querySelector('.nfq-ac-list');
        if (!list) return;
        list.innerHTML = inst.suggestions.map((sg, i) => {
            const selected = i === inst.selectedIndex ? ' nfq-ac-selected' : '';
            return '<div class="nfq-ac-item' + selected + '" data-index="' + i + '" role="option"'
                + (selected ? ' aria-selected="true"' : '') + '>'
                + '<span class="nfq-ac-icon">' + (sg.icon || '•') + '</span>'
                + '<span class="nfq-ac-text">' + escapeHtml(sg.text) + '</span>'
                + '<span class="nfq-ac-desc">' + escapeHtml(sg.desc || '') + '</span>'
                + '</div>';
        }).join('');
        list.style.maxHeight = (8 * 32) + 'px';
    }

    function scrollToSelected(inst) {
        if (!popup) return;
        const sel = popup.querySelector('.nfq-ac-selected');
        if (sel) sel.scrollIntoView({ block: 'nearest' });
    }

    function positionPopup(inst) {
        if (!popup) return;
        const ta = inst.textarea;
        const coords = getCaretCoordinates(ta);
        const r = ta.getBoundingClientRect();
        let left = r.left + coords.left - ta.scrollLeft;
        let top = r.top + coords.top - ta.scrollTop + coords.lineHeight;
        const pw = 380, ph = 280;
        if (left + pw > window.innerWidth) left = window.innerWidth - pw - 8;
        if (left < 4) left = 4;
        if (top + ph > window.innerHeight) top = r.top + coords.top - ta.scrollTop - ph - 4;
        popup.style.left = Math.round(left) + 'px';
        popup.style.top = Math.round(top) + 'px';
        popup.style.width = pw + 'px';
    }

    function getCaretCoordinates(textarea) {
        const m = ensureMirror();
        const computed = window.getComputedStyle(textarea);
        const props = ['fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'letterSpacing',
            'lineHeight', 'textTransform', 'wordWrap', 'wordSpacing', 'whiteSpace',
            'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft',
            'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth',
            'boxSizing', 'textIndent', 'overflowWrap', 'tabSize'];
        m.style.cssText = 'position:absolute;visibility:hidden;overflow:hidden;pointer-events:none;';
        for (const prop of props) m.style[prop] = computed[prop];
        m.style.width = computed.width;
        m.style.height = 'auto';
        m.style.whiteSpace = 'pre-wrap';
        m.style.wordBreak = 'break-word';
        const text = textarea.value;
        const pos = textarea.selectionStart;
        m.textContent = '';
        m.appendChild(document.createTextNode(text.substring(0, pos)));
        const caret = document.createElement('span');
        caret.textContent = '|';
        m.appendChild(caret);
        m.appendChild(document.createTextNode(text.substring(pos) || ' '));
        const lineHeight = parseInt(computed.lineHeight, 10) || parseInt(computed.fontSize, 10) * 1.4;
        return { left: caret.offsetLeft, top: caret.offsetTop, lineHeight };
    }

    function escapeHtml(text) {
        if (!text) return '';
        return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { attach, detach, detachAll, loadFiles, refreshFiles };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = NfqwsAutocomplete;
