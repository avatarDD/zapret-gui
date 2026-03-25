/**
 * autocomplete.js — Синтаксис-помощник (autocomplete) для параметров nfqws/nfqws2.
 *
 * Выпадающий popup с контекстными подсказками при вводе стратегий.
 * Использует данные из NfqwsSyntax (PARAMS, SUB_PARAMS, DESYNC_METHODS, …).
 *
 * API:
 *   NfqwsAutocomplete.attach(textarea)   — подключить к textarea
 *   NfqwsAutocomplete.detach(textarea)   — отключить от textarea
 *   NfqwsAutocomplete.detachAll()        — отключить все
 *   NfqwsAutocomplete.loadFiles()        — загрузить файлы (blobs, hostlists, ipsets) с сервера
 */

const NfqwsAutocomplete = (() => {

    // ══════════════════ Состояние ══════════════════

    const instances = new Map();   // textarea → instance
    let popup = null;              // единственный popup-элемент
    let mirror = null;             // зеркало для вычисления координат курсора
    let activeInstance = null;     // текущий активный instance

    // Кеш файлов с сервера
    let fileCache = { blobs: null, hostlists: null, ipsets: null, ts: 0 };
    const FILE_CACHE_TTL = 60000; // 60 сек

    // Категории и их цвета (CSS-класс суффикс)
    const CAT_ICONS = {
        filter:  '🔵', desync:  '🔴', list:    '🟢',
        global:  '🟡', dup:     '🟠', payload: '🟣',
        special: '⚪', limit:   '🟡', method:  '🔴',
        sub:     '🟢', l7:      '🟣', fooling: '🟠',
        pos:     '🟢', tlsmod:  '🔴', file:    '📄',
        value:   '⚪',
    };

    // ══════════════════ Popup DOM ══════════════════

    function ensurePopup() {
        if (popup) return popup;
        popup = document.createElement('div');
        popup.className = 'nfq-ac-popup';
        popup.style.display = 'none';
        popup.setAttribute('role', 'listbox');
        popup.innerHTML = '<div class="nfq-ac-list"></div>';
        document.body.appendChild(popup);

        // Клик внутри popup — вставляем выбранный элемент
        popup.addEventListener('mousedown', (e) => {
            e.preventDefault(); // Не терять фокус textarea
            const item = e.target.closest('.nfq-ac-item');
            if (item && activeInstance) {
                const idx = parseInt(item.dataset.index, 10);
                insertSuggestion(activeInstance, idx);
            }
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

        const inst = {
            textarea,
            suggestions: [],
            selectedIndex: -1,
            visible: false,
        };

        const onInput  = () => handleInput(inst);
        const onKeyDown = (e) => handleKeyDown(inst, e);
        const onBlur   = () => { setTimeout(() => hidePopup(inst), 150); };
        const onScroll = () => { if (inst.visible) positionPopup(inst); };

        inst._onInput   = onInput;
        inst._onKeyDown = onKeyDown;
        inst._onBlur    = onBlur;
        inst._onScroll  = onScroll;

        textarea.addEventListener('input', onInput);
        textarea.addEventListener('keydown', onKeyDown);
        textarea.addEventListener('blur', onBlur);
        textarea.addEventListener('scroll', onScroll);

        // Ctrl+Space
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

        if (activeInstance === inst) {
            hidePopup(inst);
            activeInstance = null;
        }

        instances.delete(textarea);
    }

    function detachAll() {
        for (const [textarea] of instances) {
            detach(textarea);
        }
        if (popup) {
            popup.style.display = 'none';
        }
    }

    // ══════════════════ Обработка ввода ══════════════════

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
        // Ctrl+Space — ручной вызов
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
                renderItems(inst);
                scrollToSelected(inst);
                break;

            case 'ArrowUp':
                e.preventDefault();
                inst.selectedIndex = (inst.selectedIndex - 1 + inst.suggestions.length) % inst.suggestions.length;
                renderItems(inst);
                scrollToSelected(inst);
                break;

            case 'Enter':
            case 'Tab':
                if (inst.selectedIndex >= 0 && inst.selectedIndex < inst.suggestions.length) {
                    e.preventDefault();
                    insertSuggestion(inst, inst.selectedIndex);
                }
                break;

            case 'Escape':
                e.preventDefault();
                hidePopup(inst);
                break;
        }
    }

    // ══════════════════ Определение контекста ══════════════════

    function getContext(textarea) {
        const text = textarea.value;
        const cursorPos = textarea.selectionStart;
        const before = text.substring(0, cursorPos);

        // Находим начало текущего токена (после последнего пробела)
        const lastSpace = before.lastIndexOf(' ');
        const tokenStart = lastSpace + 1;
        const currentToken = before.substring(tokenStart);

        // Если набирает начало флага
        if (currentToken.startsWith('--')) {
            // Проверяем нет ли = внутри (значение флага)
            const eqIdx = currentToken.indexOf('=');
            if (eqIdx < 0) {
                // Набираем имя флага
                return { type: 'flag', prefix: currentToken, tokenStart: tokenStart };
            }
            // Есть = → значение
            const flag = currentToken.substring(0, eqIdx);
            const valueStr = currentToken.substring(eqIdx + 1);
            const valueStart = tokenStart + eqIdx + 1;

            // --lua-desync: разбор цепочки через :
            if (flag === '--lua-desync') {
                return parseLuaDesyncContext(valueStr, valueStart);
            }

            // --dpi-desync: значения через запятую (методы)
            if (flag === '--dpi-desync') {
                return parseCommaList(valueStr, valueStart, 'method');
            }

            // --dpi-desync-fooling / --dup-fooling
            if (flag === '--dpi-desync-fooling' || flag === '--dup-fooling') {
                return parseCommaList(valueStr, valueStart, 'fooling');
            }

            // --filter-l7
            if (flag === '--filter-l7') {
                return parseCommaList(valueStr, valueStart, 'l7');
            }

            // --dpi-desync-split-pos
            if (flag === '--dpi-desync-split-pos') {
                return parseCommaList(valueStr, valueStart, 'pos');
            }

            // --dpi-desync-fake-tls-mod
            if (flag === '--dpi-desync-fake-tls-mod') {
                return parseCommaList(valueStr, valueStart, 'tlsmod');
            }

            // --hostlist, --hostlist-exclude → файлы hostlists
            if (flag === '--hostlist' || flag === '--hostlist-exclude' || flag === '--hostlist-auto') {
                return { type: 'file', fileType: 'hostlist', prefix: valueStr, tokenStart: valueStart };
            }

            // --ipset, --ipset-exclude → файлы ipsets
            if (flag === '--ipset' || flag === '--ipset-exclude') {
                return { type: 'file', fileType: 'ipset', prefix: valueStr, tokenStart: valueStart };
            }

            // --dpi-desync-fake-tls, --dpi-desync-fake-http, --dpi-desync-fake-quic и прочие fake-файлы
            if (/^--dpi-desync-fake/.test(flag) && flag !== '--dpi-desync-fake-tls-mod') {
                return { type: 'file', fileType: 'blob', prefix: valueStr, tokenStart: valueStart };
            }

            // Общий случай — подсказать из PARAMS[flag].values
            const paramInfo = NfqwsSyntax.PARAMS[flag];
            if (paramInfo && paramInfo.values && paramInfo.values.length > 0) {
                return { type: 'value', flag: flag, prefix: valueStr, tokenStart: valueStart, values: paramInfo.values };
            }

            return null;
        }

        // Пустой ввод или после пробела — подсказать все флаги
        if (currentToken === '' || currentToken.startsWith('-')) {
            return { type: 'flag', prefix: currentToken, tokenStart: tokenStart };
        }

        return null;
    }

    function parseLuaDesyncContext(valueStr, valueStart) {
        const parts = valueStr.split(':');

        if (parts.length === 1) {
            // Первая часть — desync-метод
            return { type: 'method', prefix: parts[0], tokenStart: valueStart };
        }

        // Несколько частей — последняя определяет контекст
        const lastPart = parts[parts.length - 1];
        const lastPartStart = valueStart + valueStr.lastIndexOf(':') + 1;
        const eqIdx = lastPart.indexOf('=');

        if (eqIdx >= 0) {
            // Есть = → значение субпараметра
            const subkey = lastPart.substring(0, eqIdx);
            const subval = lastPart.substring(eqIdx + 1);
            const subvalStart = lastPartStart + eqIdx + 1;

            // blob= → подсказать файлы блобов
            if (subkey === 'blob') {
                return { type: 'file', fileType: 'blob', prefix: subval, tokenStart: subvalStart, isLuaBlob: true };
            }

            // pos= → позиции
            if (subkey === 'pos') {
                return parseCommaList(subval, subvalStart, 'pos');
            }

            // fooling= → методы fooling
            if (subkey === 'fooling') {
                return parseCommaList(subval, subvalStart, 'fooling');
            }

            // Подсказать значения из SUB_PARAMS
            const subInfo = NfqwsSyntax.SUB_PARAMS[subkey];
            if (subInfo && subInfo.values && subInfo.values.length > 0) {
                return { type: 'subvalue', key: subkey, prefix: subval, tokenStart: subvalStart, values: subInfo.values };
            }

            return null;
        }

        // Нет = → набирает имя субпараметра
        // Собираем уже введённые субпараметры (чтобы не дублировать)
        const already = [];
        for (let i = 1; i < parts.length - 1; i++) {
            const eq = parts[i].indexOf('=');
            already.push(eq >= 0 ? parts[i].substring(0, eq) : parts[i]);
        }

        return { type: 'sub', prefix: lastPart, tokenStart: lastPartStart, already: already };
    }

    function parseCommaList(valueStr, valueStart, listType) {
        const items = valueStr.split(',');
        const lastItem = items[items.length - 1];
        const lastItemStart = valueStart + valueStr.lastIndexOf(',') + 1;
        if (items.length === 1) {
            // Первый (или единственный) элемент
            return { type: listType, prefix: lastItem, tokenStart: valueStart, already: [] };
        }
        return { type: listType, prefix: lastItem, tokenStart: lastItemStart, already: items.slice(0, -1) };
    }

    // ══════════════════ Построение подсказок ══════════════════

    function buildSuggestions(ctx) {
        switch (ctx.type) {
            case 'flag':    return buildFlagSuggestions(ctx.prefix);
            case 'method':  return buildMethodSuggestions(ctx.prefix, ctx.already);
            case 'sub':     return buildSubSuggestions(ctx.prefix, ctx.already);
            case 'subvalue':return buildSubValueSuggestions(ctx.key, ctx.prefix, ctx.values);
            case 'fooling': return buildFoolingSuggestions(ctx.prefix, ctx.already);
            case 'l7':      return buildL7Suggestions(ctx.prefix, ctx.already);
            case 'pos':     return buildPosSuggestions(ctx.prefix);
            case 'tlsmod':  return buildTlsModSuggestions(ctx.prefix, ctx.already);
            case 'value':   return buildValueSuggestions(ctx.flag, ctx.prefix, ctx.values);
            case 'file':    return buildFileSuggestions(ctx.fileType, ctx.prefix, ctx.isLuaBlob);
            default:        return [];
        }
    }

    function buildFlagSuggestions(prefix) {
        const p = (prefix || '').toLowerCase();
        const results = [];
        for (const [key, info] of Object.entries(NfqwsSyntax.PARAMS)) {
            if (key === '--new') continue; // Не подсказываем --new (особый)
            if (!p || key.toLowerCase().startsWith(p)) {
                const needsEq = info.values !== undefined; // Почти все кроме бесформатных
                results.push({
                    text: key,
                    insert: key + (needsEq && info.cat !== 'special' ? '=' : ' '),
                    desc: info.desc,
                    cat: info.cat,
                    icon: CAT_ICONS[info.cat] || '⚪',
                });
            }
        }
        return results.slice(0, 40);
    }

    function buildMethodSuggestions(prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(s => s.toLowerCase()));
        const results = [];
        for (const m of NfqwsSyntax.DESYNC_METHODS) {
            if (skip.has(m)) continue;
            if (!p || m.startsWith(p)) {
                results.push({
                    text: m,
                    insert: m,
                    desc: 'Desync метод',
                    cat: 'method',
                    icon: CAT_ICONS.method,
                });
            }
        }
        return results;
    }

    function buildSubSuggestions(prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(s => s.toLowerCase()));
        const results = [];
        for (const [key, info] of Object.entries(NfqwsSyntax.SUB_PARAMS)) {
            if (skip.has(key)) continue;
            if (!p || key.toLowerCase().startsWith(p)) {
                const hasValues = info.values && info.values.length > 0;
                results.push({
                    text: key,
                    insert: key + (hasValues ? '=' : ''),
                    desc: info.desc,
                    cat: 'sub',
                    icon: CAT_ICONS.sub,
                });
            }
        }
        return results;
    }

    function buildSubValueSuggestions(key, prefix, values) {
        const p = (prefix || '').toLowerCase();
        return (values || []).filter(v => !p || v.toLowerCase().startsWith(p)).map(v => ({
            text: v, insert: v, desc: key, cat: 'value', icon: CAT_ICONS.value,
        }));
    }

    function buildFoolingSuggestions(prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(s => s.toLowerCase()));
        return NfqwsSyntax.FOOLING_METHODS
            .filter(m => !skip.has(m) && (!p || m.startsWith(p)))
            .map(m => ({ text: m, insert: m, desc: 'Fooling метод', cat: 'fooling', icon: CAT_ICONS.fooling }));
    }

    function buildL7Suggestions(prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(s => s.toLowerCase()));
        return NfqwsSyntax.L7_PROTOCOLS
            .filter(m => !skip.has(m) && (!p || m.startsWith(p)))
            .map(m => ({ text: m, insert: m, desc: 'L7 протокол', cat: 'l7', icon: CAT_ICONS.l7 }));
    }

    function buildPosSuggestions(prefix) {
        const p = (prefix || '').toLowerCase();
        const positions = ['1', 'midsld', 'midhost', 'sld+1', 'method+2', 'host+1', 'endhost-1'];
        return positions
            .filter(v => !p || v.startsWith(p))
            .map(v => ({ text: v, insert: v, desc: 'Позиция', cat: 'pos', icon: CAT_ICONS.pos }));
    }

    function buildTlsModSuggestions(prefix, already) {
        const p = (prefix || '').toLowerCase();
        const skip = new Set((already || []).map(s => s.toLowerCase()));
        const mods = ['rnd', 'rndsni', 'dupsid', 'padencap', 'none'];
        return mods
            .filter(m => !skip.has(m) && (!p || m.startsWith(p)))
            .map(m => ({ text: m, insert: m, desc: 'TLS модификация', cat: 'tlsmod', icon: CAT_ICONS.tlsmod }));
    }

    function buildValueSuggestions(flag, prefix, values) {
        const p = (prefix || '').toLowerCase();
        const info = NfqwsSyntax.PARAMS[flag];
        const cat = info ? info.cat : 'value';
        return (values || []).filter(v => !p || v.toLowerCase().startsWith(p)).map(v => ({
            text: v, insert: v, desc: flag, cat: cat, icon: CAT_ICONS[cat] || '⚪',
        }));
    }

    function buildFileSuggestions(fileType, prefix, isLuaBlob) {
        const p = (prefix || '').toLowerCase();
        const results = [];

        // Статические дефолты из SUB_PARAMS для blob
        if (fileType === 'blob') {
            const defaults = (NfqwsSyntax.SUB_PARAMS['blob'] || {}).values || [];
            for (const name of defaults) {
                if (!p || name.toLowerCase().startsWith(p)) {
                    results.push({
                        text: name,
                        insert: name,
                        desc: isLuaBlob ? 'Встроенный блоб' : 'Файл блоба',
                        cat: 'file',
                        icon: CAT_ICONS.file,
                    });
                }
            }
        }

        // Файлы с сервера (кешированные)
        const files = getCachedFiles(fileType);
        if (files) {
            for (const f of files) {
                const name = f.name || f;
                if (!p || name.toLowerCase().startsWith(p)) {
                    // Не дублируем дефолтные блобы
                    if (!results.find(r => r.text === name)) {
                        let path = name;
                        // Для классического nfqws (не lua blob) — нужен полный путь
                        if (fileType === 'blob' && !isLuaBlob) {
                            path = f.path || name;
                        } else if (fileType === 'hostlist') {
                            path = f.path || name;
                        } else if (fileType === 'ipset') {
                            path = f.path || name;
                        }
                        results.push({
                            text: name,
                            insert: path,
                            desc: fileType === 'blob' ? 'Блоб' : fileType === 'hostlist' ? 'Список хостов' : 'IP-список',
                            cat: 'file',
                            icon: CAT_ICONS.file,
                        });
                    }
                }
            }
        }

        return results.slice(0, 20);
    }

    // ══════════════════ Кеш файлов ══════════════════

    function getCachedFiles(type) {
        if (!fileCache[type]) return null;
        return fileCache[type];
    }

    function loadFiles() {
        if (Date.now() - fileCache.ts < FILE_CACHE_TTL) return;

        // Загружаем параллельно, не блокируя
        const loadOne = (endpoint, key) => {
            fetch('/api/' + endpoint)
                .then(r => r.ok ? r.json() : null)
                .then(data => {
                    if (data) {
                        if (key === 'blobs') {
                            fileCache.blobs = (data.blobs || []).map(b => ({
                                name: b.name || b,
                                path: b.path || b.name || b,
                            }));
                        } else if (key === 'hostlists') {
                            fileCache.hostlists = (data.files || data.hostlists || []).map(h => ({
                                name: h.name || h,
                                path: h.path || h.name || h,
                            }));
                        } else if (key === 'ipsets') {
                            fileCache.ipsets = (data.files || data.ipsets || []).map(ip => ({
                                name: ip.name || ip,
                                path: ip.path || ip.name || ip,
                            }));
                        }
                    }
                })
                .catch(() => { /* ignore - подсказки файлов просто не появятся */ });
        };

        loadOne('blobs', 'blobs');
        loadOne('hostlists', 'hostlists');
        loadOne('ipsets', 'ipsets');
        fileCache.ts = Date.now();
    }

    // ══════════════════ Вставка выбранного ══════════════════

    function insertSuggestion(inst, index) {
        const s = inst.suggestions[index];
        if (!s) return;

        const ta = inst.textarea;
        const text = ta.value;
        const cursorPos = ta.selectionStart;
        const ctx = getContext(ta);
        if (!ctx) { hidePopup(inst); return; }

        let replaceStart, replaceEnd, insertText;

        if (ctx.type === 'flag') {
            // Заменяем от tokenStart до курсора
            replaceStart = ctx.tokenStart;
            replaceEnd = cursorPos;
            insertText = s.insert;
        } else {
            // Для значений — tokenStart из контекста
            replaceStart = ctx.tokenStart;
            replaceEnd = cursorPos;
            insertText = s.insert;
        }

        const before = text.substring(0, replaceStart);
        const after = text.substring(replaceEnd);

        ta.value = before + insertText + after;
        const newPos = replaceStart + insertText.length;
        ta.selectionStart = ta.selectionEnd = newPos;

        // Триггерим events для сохранения данных
        ta.dispatchEvent(new Event('input', { bubbles: true }));
        ta.dispatchEvent(new Event('change', { bubbles: true }));

        hidePopup(inst);
        ta.focus();

        // Для флагов без = и subparam-флагов без значения — добавляем пробел если нет
        // (уже добавлено в insert для флагов)
    }

    // ══════════════════ Popup: показать / скрыть / позиционировать ══════════════════

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

        const maxVisible = 8;
        const items = inst.suggestions;

        list.innerHTML = items.map((s, i) => {
            const selected = i === inst.selectedIndex ? ' nfq-ac-selected' : '';
            return '<div class="nfq-ac-item' + selected + '" data-index="' + i + '" role="option"' +
                (selected ? ' aria-selected="true"' : '') + '>' +
                '<span class="nfq-ac-icon">' + (s.icon || '⚪') + '</span>' +
                '<span class="nfq-ac-text">' + escapeHtml(s.text) + '</span>' +
                '<span class="nfq-ac-desc">' + escapeHtml(s.desc) + '</span>' +
                '</div>';
        }).join('');

        // Ограничиваем высоту
        list.style.maxHeight = (maxVisible * 32) + 'px';
    }

    function scrollToSelected(inst) {
        if (!popup) return;
        const list = popup.querySelector('.nfq-ac-list');
        const selected = list && list.querySelector('.nfq-ac-selected');
        if (selected) {
            selected.scrollIntoView({ block: 'nearest' });
        }
    }

    function positionPopup(inst) {
        if (!popup) return;
        const ta = inst.textarea;
        const coords = getCaretCoordinates(ta);
        const taRect = ta.getBoundingClientRect();

        let left = taRect.left + coords.left - ta.scrollLeft;
        let top = taRect.top + coords.top - ta.scrollTop + coords.lineHeight;

        // Убеждаемся что popup не выходит за экран
        const popupWidth = 360;
        const popupHeight = 260;

        if (left + popupWidth > window.innerWidth) {
            left = window.innerWidth - popupWidth - 8;
        }
        if (left < 4) left = 4;

        if (top + popupHeight > window.innerHeight) {
            // Показываем над курсором
            top = taRect.top + coords.top - ta.scrollTop - popupHeight - 4;
        }

        popup.style.left = Math.round(left) + 'px';
        popup.style.top = Math.round(top) + 'px';
        popup.style.width = popupWidth + 'px';
    }

    // ══════════════════ Координаты каретки (mirror-div) ══════════════════

    function getCaretCoordinates(textarea) {
        const m = ensureMirror();
        const computed = window.getComputedStyle(textarea);

        // Копируем стили textarea
        const props = [
            'fontFamily', 'fontSize', 'fontWeight', 'fontStyle',
            'letterSpacing', 'lineHeight', 'textTransform',
            'wordWrap', 'wordSpacing', 'whiteSpace',
            'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft',
            'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth',
            'boxSizing', 'textIndent', 'overflowWrap', 'tabSize',
        ];

        m.style.cssText = 'position:absolute;visibility:hidden;overflow:hidden;pointer-events:none;';
        for (const prop of props) {
            m.style[prop] = computed[prop];
        }
        m.style.width = computed.width;
        m.style.height = 'auto';
        m.style.whiteSpace = 'pre-wrap';
        m.style.wordBreak = 'break-word';

        const text = textarea.value;
        const pos = textarea.selectionStart;
        const beforeCursor = text.substring(0, pos);
        const afterCursor = text.substring(pos) || ' ';

        m.textContent = '';
        const beforeSpan = document.createTextNode(beforeCursor);
        const caret = document.createElement('span');
        caret.textContent = '|';
        caret.id = '_nfq_ac_caret';
        const afterSpan = document.createTextNode(afterCursor);

        m.appendChild(beforeSpan);
        m.appendChild(caret);
        m.appendChild(afterSpan);

        const lineHeight = parseInt(computed.lineHeight, 10) || parseInt(computed.fontSize, 10) * 1.4;

        return {
            left: caret.offsetLeft,
            top: caret.offsetTop,
            lineHeight: lineHeight,
        };
    }

    // ══════════════════ Утилиты ══════════════════

    function escapeHtml(text) {
        if (!text) return '';
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ══════════════════ Public API ══════════════════

    return {
        attach,
        detach,
        detachAll,
        loadFiles,
    };

})();
