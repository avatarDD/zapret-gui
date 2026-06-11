/**
 * proxy_table.js — переиспользуемая Throne-подобная таблица проксей.
 *
 * Один компонент вместо копипасты singbox_proxies/mihomo_proxies:
 * колонки Имя | Тип | Адрес | Задержка/статус | Трафик ↑/↓ и вся общая
 * механика:
 *   - выбор строк (клик / Ctrl+клик / Shift-диапазон / чекбоксы);
 *   - сортируемые заголовки (доступность/задержка/трафик/имя/тип/адрес);
 *   - тест выделенных/всех с прогрессом (TCP-отсев + e2e);
 *   - копирование выделенных share-ссылками (Ctrl+C) и вставка из
 *     буфера (Ctrl+V) — событием `paste`, работает и без HTTPS;
 *   - активация по двойному клику / кнопке «Через эту»;
 *   - учёт трафика per-proxy (поллинг раз в 3с, обновление ячеек на
 *     месте — без сброса фокуса/сортировки под рукой);
 *   - хоткеи Ctrl/⌘+C, Ctrl/⌘+A, Delete (когда фокус не в поле ввода).
 *
 * Специфика движка (эндпоинты, баннеры clash_api/external-controller,
 * «битые ключи», debug-режим) выносится в адаптер — см. opts ниже.
 *
 * Использование (страница — тонкий адаптер):
 *   const SingboxProxiesPage = ProxyTable.create({
 *       globalName: 'SingboxProxiesPage',  // для inline-onclick
 *       bodyId: 'px-body',
 *       title, description, backHash, backLabel, labels: {...},
 *       loadConfigs() -> [{name, running}],
 *       loadItems(ctx, name) -> {items:[{id,type,address,raw}], activeId, running?, extra?},
 *       loadTraffic(ctx, name) -> {traffic:{id:{up,down}}, extra?} | null,
 *       startTest(ctx, selectedOnly) -> r,     testStatusUrl: '…/test/status',
 *       exportLinks(ctx) -> r,  importLinks(ctx, text) -> r,
 *       deleteItems(ctx, ids) -> r,  activate(ctx, id),
 *       // хуки отображения (все опциональны):
 *       configOptionLabel(c), statusInlineHtml(st), bannersHtml(st),
 *       toolbarExtraHtml(st), belowToolbarHtml(st), panelsHtml(st),
 *       testCellOverride(id, st), trafficNeedsRender(prevExtra, extra),
 *       emptyConfigsHtml(), emptyItemsHtml(st), testDoneExtra(result),
 *       pickDefaultConfig(configs), onSwitchConfig(ctx), init(ctx),
 *       extraMethods: { name: (ctx, ...args) => {} },  // в public API
 *   });
 *
 * ctx, передаваемый адаптеру: { state, renderBody, loadItems,
 * loadTraffic, reload } — state мутабелен (extra — движко-специфичное).
 */
const ProxyTable = (() => {

    // ══════════════ общие хелперы ══════════════

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escAttr(s) {
        return esc(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function humanBytes(n) {
        n = Number(n) || 0;
        if (n < 1024) return n + ' B';
        const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
        do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
        return (n < 10 ? n.toFixed(2) : n.toFixed(1)) + ' ' + u[i];
    }

    async function copyText(text) {
        // Secure-context (localhost/https) — Clipboard API.
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (_) { /* упадём на fallback */ }
        // Fallback для http на роутере: скрытая textarea + execCommand.
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus(); ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (_) { return false; }
    }

    function isEditable(el) {
        if (!el) return false;
        const tag = (el.tagName || '').toLowerCase();
        return tag === 'input' || tag === 'textarea' || tag === 'select'
               || el.isContentEditable;
    }

    // ══════════════ фабрика страницы ══════════════

    function create(opts) {
        const G = opts.globalName;
        const L = Object.assign({
            // слова, различающиеся между движками («сервер» / «узел»)
            countWord:    'серверов',
            testNoun:     'серверов',
            itemOneAcc:   'сервер',          // «Выберите один сервер»
            itemsAcc:     'серверы',         // «Удалить выбранные серверы…»
            rowTitle:     'Двойной клик — пустить трафик через этот сервер',
            activeMark:   'активный сервер',
            activateTitle:'Пустить трафик через выделенный сервер (двойной клик по строке)',
            noLinks:      'Нет ссылок для копирования',
        }, opts.labels || {});

        const state = {
            configs: [],
            configName: '',
            items: [],            // [{id, type, address, raw}]
            activeId: '',         // активный сервер/узел
            running: false,
            extra: {},            // движко-специфичное (clash/controller/debug…)
            testResults: {},      // id -> {alive, latency_ms, stage, error}
            traffic: {},          // id -> {up, down}
            selected: new Set(),  // выбранные id
            lastClickedIdx: -1,   // для Shift-диапазона (в отсорт. виде)
            sortKey: 'avail',
            sortDir: 'desc',      // desc: лучшие сверху
            target: 'cloudflare',
            testState: { running: false, progress: { phase: '', done: 0, total: 0 } },
            showPasteBox: false,
            busy: false,
        };

        let testTimer = null;
        let trafficTimer = null;
        // Слушатели на document — снимаем в destroy().
        let keyHandler = null;
        let pasteHandler = null;

        const ctx = {
            state,
            renderBody,
            loadItems,
            loadTraffic,
            reload: async () => { await loadItems(); await loadTraffic(); renderBody(); },
        };

        // ══════════════ lifecycle ══════════════

        function render(container) {
            container.innerHTML = `
                <div class="page-header">
                    <div>
                        <h1 class="page-title">${esc(opts.title || 'Прокси')}</h1>
                        <p class="page-description">${opts.description || ''}</p>
                    </div>
                    <div style="display:flex; gap:8px;">
                        ${opts.backHash ? `
                        <button class="btn btn-ghost btn-sm"
                                onclick="window.location.hash='${escAttr(opts.backHash)}'">
                            ${esc(opts.backLabel || 'Назад')}
                        </button>` : ''}
                        <button class="btn btn-ghost btn-sm" onclick="${G}.refreshAll()">
                            Обновить
                        </button>
                    </div>
                </div>
                <div id="${opts.bodyId}"></div>
            `;
            attachGlobalHandlers();
            if (opts.init) opts.init(ctx);
            loadConfigs();
            startTrafficPolling();
        }

        function destroy() {
            if (testTimer) { clearTimeout(testTimer); testTimer = null; }
            if (trafficTimer) { clearTimeout(trafficTimer); trafficTimer = null; }
            detachGlobalHandlers();
        }

        // ══════════════ data ══════════════

        async function loadConfigs() {
            try {
                state.configs = (await opts.loadConfigs()) || [];
            } catch (e) { Toast.error(e.message); state.configs = []; }

            if (!state.configName
                || !state.configs.some(c => c.name === state.configName)) {
                state.configName = opts.pickDefaultConfig
                    ? (opts.pickDefaultConfig(state.configs) || '')
                    : ((state.configs[0] || {}).name || '');
            }
            await loadItems();
            await loadTraffic();
            renderBody();
        }

        async function loadItems() {
            state.items = [];
            state.activeId = '';
            state.running = false;
            if (!state.configName) return;
            try {
                const r = await opts.loadItems(ctx, state.configName);
                if (r) {
                    state.items = r.items || [];
                    state.activeId = r.activeId || '';
                    state.running = !!r.running;
                    // extra мержим (не заменяем): часть ключей живёт от
                    // loadTraffic (clash_api), часть — от loadItems.
                    if (r.extra) Object.assign(state.extra, r.extra);
                }
            } catch (e) { Toast.error(e.message); }
            // Чистим выбор от исчезнувших id.
            const present = new Set(state.items.map(i => i.id));
            state.selected = new Set([...state.selected].filter(t => present.has(t)));
        }

        async function loadTraffic() {
            if (!state.configName) {
                state.traffic = {};
                if (opts.emptyTrafficExtra) Object.assign(state.extra, opts.emptyTrafficExtra);
                return;
            }
            try {
                const r = await opts.loadTraffic(ctx, state.configName);
                if (r) {
                    state.traffic = r.traffic || {};
                    if (r.extra) Object.assign(state.extra, r.extra);
                }
            } catch (_) { /* трафик не критичен */ }
        }

        function startTrafficPolling() {
            if (trafficTimer) clearTimeout(trafficTimer);
            trafficTimer = setTimeout(async () => {
                const prevExtra = Object.assign({}, state.extra);
                await loadTraffic();
                // Не делаем полную перерисовку (она сбросила бы фокус/поле
                // вставки и пересортировала бы строки под рукой) — обновляем
                // только значения трафика на месте. Полный re-render лишь
                // когда адаптер скажет, что изменилось что-то видимое
                // (например появился/исчез баннер clash_api).
                if (document.getElementById(opts.bodyId)) {
                    if (opts.trafficNeedsRender
                        && opts.trafficNeedsRender(prevExtra, state.extra)) {
                        renderBody();
                    } else {
                        updateTrafficCells();
                    }
                }
                startTrafficPolling();
            }, 3000);
        }

        function updateTrafficCells() {
            const body = document.getElementById(opts.bodyId);
            if (!body) return;
            body.querySelectorAll('tr[data-id]').forEach(tr => {
                const cell = tr.querySelector('.pt-traffic');
                if (cell) cell.innerHTML = trafficCellHtml(tr.getAttribute('data-id'));
            });
        }

        async function refreshAll() { await loadConfigs(); }

        function switchConfig(name) {
            state.configName = name;
            state.selected = new Set();
            state.lastClickedIdx = -1;
            state.testResults = {};
            if (opts.onSwitchConfig) opts.onSwitchConfig(ctx);
            loadItems().then(loadTraffic).then(renderBody);
        }

        // ══════════════ render ══════════════

        function renderBody() {
            const box = document.getElementById(opts.bodyId);
            if (!box) return;

            if (!state.configs.length) {
                box.innerHTML = opts.emptyConfigsHtml
                    ? opts.emptyConfigsHtml()
                    : `<div class="card"><div class="text-muted">Конфигов нет.</div></div>`;
                return;
            }

            const cfgOpts = state.configs.map(c =>
                `<option value="${escAttr(c.name)}" ${c.name === state.configName ? 'selected' : ''}>
                    ${esc(c.name)}${esc(opts.configOptionLabel ? (opts.configOptionLabel(c) || '') : (c.running ? ' ●' : ''))}
                </option>`).join('');

            const selCount = state.selected.size;
            box.innerHTML = `
                <div class="card" style="margin-bottom:12px;">
                    <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <label class="text-muted" style="margin:0;">Конфиг:</label>
                        <select class="form-input" style="width:auto;"
                                onchange="${G}.switchConfig(this.value)">
                            ${cfgOpts}
                        </select>
                        <span class="text-muted" style="font-size:12px;">
                            ${L.countWord}: ${state.items.length}${selCount ? ` · выбрано: ${selCount}` : ''}
                            ${opts.statusInlineHtml ? (opts.statusInlineHtml(state) || '') : ''}
                        </span>
                        <div style="margin-left:auto; display:flex; gap:6px; flex-wrap:wrap;">
                            <label class="text-muted expert-only" style="display:flex; align-items:center; gap:4px; font-size:12px;">
                                цель
                                <select class="form-input" style="width:auto;"
                                        onchange="${G}.setTarget(this.value)">
                                    ${['cloudflare', 'amazon', 'google'].map(t =>
                                        `<option value="${t}" ${t === state.target ? 'selected' : ''}>${t}</option>`).join('')}
                                </select>
                            </label>
                            <button class="btn btn-primary btn-sm" ${state.testState.running || state.busy ? 'disabled' : ''}
                                    onclick="${G}.test(false)">
                                ${state.testState.running ? 'Тест идёт…' : 'Тест всех'}
                            </button>
                            <button class="btn btn-ghost btn-sm" ${state.testState.running || state.busy || !selCount ? 'disabled' : ''}
                                    onclick="${G}.test(true)">
                                Тест выделенных
                            </button>
                            <button class="btn btn-primary btn-sm" ${state.busy || selCount !== 1 ? 'disabled' : ''}
                                    onclick="${G}.activateSelected()"
                                    title="${escAttr(L.activateTitle)}">
                                ▶ Через эту
                            </button>
                            <button class="btn btn-ghost btn-sm" ${!selCount ? 'disabled' : ''}
                                    onclick="${G}.copySelected()" title="Ctrl+C">
                                Копировать
                            </button>
                            <button class="btn btn-ghost btn-sm"
                                    onclick="${G}.togglePasteBox()" title="Ctrl+V">
                                Вставить
                            </button>
                            <button class="btn btn-ghost btn-sm" ${!selCount || state.busy ? 'disabled' : ''}
                                    onclick="${G}.deleteSelected()" title="Delete">
                                Удалить
                            </button>
                            ${opts.toolbarExtraHtml ? (opts.toolbarExtraHtml(state) || '') : ''}
                        </div>
                    </div>
                    ${opts.belowToolbarHtml ? (opts.belowToolbarHtml(state) || '') : ''}
                    ${opts.bannersHtml ? (opts.bannersHtml(state) || '') : ''}
                    ${state.showPasteBox ? renderPasteBox() : ''}
                    ${renderTestProgress()}
                    ${opts.panelsHtml ? (opts.panelsHtml(state) || '') : ''}
                </div>

                ${renderTable()}
            `;
        }

        function renderPasteBox() {
            return `
                <div style="margin-top:10px;">
                    <label class="form-label">Вставьте ссылки (vless:// / vmess:// / trojan:// / ss:// / hy2:// / tuic://), по одной в строке:</label>
                    <textarea id="${opts.bodyId}-paste" class="form-textarea" spellcheck="false"
                              style="width:100%; min-height:90px; font-family:monospace; font-size:12px;"
                              placeholder="vless://...&#10;ss://..."></textarea>
                    <div style="margin-top:6px; display:flex; gap:6px;">
                        <button class="btn btn-primary btn-sm" onclick="${G}.importPasteBox()">
                            Импортировать
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="${G}.togglePasteBox()">
                            Отмена
                        </button>
                    </div>
                </div>`;
        }

        function renderTestProgress() {
            if (!state.testState.running) return '';
            const p = state.testState.progress || { phase: '', done: 0, total: 0 };
            const label = p.phase === 'e2e' ? 'Проверка через движок до облака' : 'TCP-отсев живых';
            const total = p.total || 0, done = p.done || 0;
            const pct = total > 0 ? Math.round((done / total) * 100) : 0;
            return `
                <div style="margin-top:12px;">
                    <div style="display:flex; justify-content:space-between; font-size:12px;">
                        <span class="text-muted">${label}…</span>
                        <span class="text-muted">${done} / ${total}${total ? ` (${pct}%)` : ''}</span>
                    </div>
                    <div style="height:6px; background:var(--bg-input); border-radius:4px; overflow:hidden; margin-top:6px;">
                        <div style="height:100%; width:${pct}%; background:var(--accent); transition:width .3s;"></div>
                    </div>
                </div>`;
        }

        function renderTable() {
            if (!state.items.length) {
                return opts.emptyItemsHtml
                    ? opts.emptyItemsHtml(state)
                    : `<div class="card"><div class="text-muted">
                        В конфиге «${esc(state.configName)}» нет серверов.
                       </div></div>`;
            }

            const rows = sortedRows();
            const allSel = rows.length && rows.every(r => state.selected.has(r.id));

            const head = (key, label, alignRight) => {
                const active = state.sortKey === key;
                const arrow = active ? (state.sortDir === 'desc' ? ' ▼' : ' ▲') : '';
                return `<th style="text-align:${alignRight ? 'right' : 'left'}; cursor:pointer; user-select:none; ${active ? 'color:var(--accent);' : ''}"
                            onclick="${G}.sortBy('${key}')">${label}${arrow}</th>`;
            };

            // Обработчики строк — по индексу в отсортированном виде, а не по
            // id в inline-onclick: имя прокси может содержать пробелы/кавычки/
            // эмодзи (mihomo) и ломать атрибут.
            const body = rows.map((r, idx) => {
                const sel = state.selected.has(r.id);
                const isActive = r.id === state.activeId;
                return `
                    <tr data-id="${escAttr(r.id)}" style="cursor:pointer; ${sel ? 'background:var(--bg-hover, rgba(120,140,255,.12));' : ''}"
                        title="${escAttr(L.rowTitle)}"
                        onclick="${G}.onRowClick(${idx}, event)"
                        ondblclick="${G}.activateIdx(${idx})">
                        <td style="width:28px; text-align:center;">
                            <input type="checkbox" ${sel ? 'checked' : ''}
                                   onclick="event.stopPropagation(); ${G}.toggleRow(${idx})">
                        </td>
                        <td>
                            ${isActive ? `<span style="color:#39c45e;" title="${escAttr(L.activeMark)}">▶</span> ` : ''}
                            <span style="font-weight:600;">${esc(r.id)}</span>
                        </td>
                        <td class="text-muted" style="font-size:11px;">${esc(r.type)}</td>
                        <td class="text-muted" style="font-size:11px;">${esc(r.address)}</td>
                        <td>${renderTestCell(r.id)}</td>
                        <td class="pt-traffic" style="text-align:right; white-space:nowrap; font-size:12px;">
                            ${trafficCellHtml(r.id)}
                        </td>
                    </tr>`;
            }).join('');

            return `
                <div class="card">
                    <div style="overflow-x:auto;">
                        <table style="width:100%; border-collapse:collapse; font-size:13px;">
                            <thead><tr style="border-bottom:1px solid var(--border,#333);">
                                <th style="width:28px; text-align:center;">
                                    <input type="checkbox" ${allSel ? 'checked' : ''}
                                           title="Выделить всё (Ctrl+A)"
                                           onclick="${G}.toggleAll(this.checked)">
                                </th>
                                ${head('name', 'Имя')}
                                ${head('type', 'Тип')}
                                ${head('address', 'Адрес')}
                                ${head('avail', 'Задержка / статус')}
                                ${head('traffic', 'Трафик', true)}
                            </tr></thead>
                            <tbody>${body}</tbody>
                        </table>
                    </div>
                </div>`;
        }

        function trafficCellHtml(id) {
            const tr = state.traffic[id] || {};
            const tt = (Number(tr.up) || 0) + (Number(tr.down) || 0);
            if (tt <= 0) return '<span class="text-muted">—</span>';
            return `<span class="text-muted">↑</span> ${humanBytes(tr.up)} `
                 + `<span class="text-muted">↓</span> ${humanBytes(tr.down)}`;
        }

        function renderTestCell(id) {
            if (opts.testCellOverride) {
                const o = opts.testCellOverride(id, state);
                if (o) return o;
            }
            const r = state.testResults[id];
            if (!r) return '<span class="text-muted">—</span>';
            const dot = r.alive ? '#39c45e' : '#e58';
            if (r.alive) {
                const lat = r.latency_ms != null ? `${r.latency_ms} ms` : 'жив';
                const stage = r.stage === 'e2e' ? 'e2e' : 'tcp';
                return `<span style="color:${dot};">●</span> ${lat}
                        <span class="text-muted" style="font-size:10px;">${stage}</span>`;
            }
            return `<span style="color:${dot};">●</span> <span style="color:#e58;">мёртв</span>
                    ${r.error ? `<span class="text-muted" style="font-size:10px;">${esc(r.error)}</span>` : ''}`;
        }

        // ══════════════ rows / sorting / selection ══════════════

        function sortedRows() {
            const rows = state.items.slice();
            const dir = state.sortDir === 'desc' ? -1 : 1;
            const lat = id => {
                const r = state.testResults[id];
                return (r && r.alive && r.latency_ms != null) ? r.latency_ms : null;
            };
            const aliveRank = id => {
                const r = state.testResults[id];
                if (!r) return 0;            // не тестировался — посередине
                return r.alive ? 1 : -1;
            };
            const traf = id => {
                const v = state.traffic[id] || {};
                return (Number(v.up) || 0) + (Number(v.down) || 0);
            };
            const cmp = (a, b) => {
                let x = 0;
                if (state.sortKey === 'name') x = String(a.id).localeCompare(String(b.id));
                else if (state.sortKey === 'type') x = String(a.type).localeCompare(String(b.type)) || String(a.id).localeCompare(String(b.id));
                else if (state.sortKey === 'address') x = String(a.address).localeCompare(String(b.address));
                else if (state.sortKey === 'traffic') x = traf(a.id) - traf(b.id);
                else if (state.sortKey === 'avail') {
                    // доступность: сначала по «жив/не тестирован/мёртв», затем
                    // по задержке (меньше — лучше, т.е. при desc сверху).
                    x = aliveRank(a.id) - aliveRank(b.id);
                    if (x === 0) {
                        const la = lat(a.id), lb = lat(b.id);
                        if (la == null && lb == null) x = 0;
                        else if (la == null) x = -1;       // без задержки — ниже живых
                        else if (lb == null) x = 1;
                        else x = lb - la;                  // меньше ms → «больше» при desc
                    }
                }
                return x * dir;
            };
            return rows.sort(cmp);
        }

        function sortBy(key) {
            if (state.sortKey === key) {
                state.sortDir = state.sortDir === 'desc' ? 'asc' : 'desc';
            } else {
                state.sortKey = key;
                // Для имени/типа/адреса логичнее по возрастанию, для метрик — убыв.
                state.sortDir = (key === 'name' || key === 'type' || key === 'address') ? 'asc' : 'desc';
            }
            state.lastClickedIdx = -1;
            renderBody();
        }

        function onRowClick(idx, event) {
            const rows = sortedRows();
            const r = rows[idx];
            if (!r) return;
            if (event && event.shiftKey && state.lastClickedIdx >= 0) {
                const [a, b] = [state.lastClickedIdx, idx].sort((x, y) => x - y);
                for (let i = a; i <= b && i < rows.length; i++) state.selected.add(rows[i].id);
            } else if (event && (event.ctrlKey || event.metaKey)) {
                if (state.selected.has(r.id)) state.selected.delete(r.id);
                else state.selected.add(r.id);
                state.lastClickedIdx = idx;
            } else {
                // Обычный клик — выделить только эту строку.
                state.selected = new Set([r.id]);
                state.lastClickedIdx = idx;
            }
            renderBody();
        }

        function toggleRow(idx) {
            const r = sortedRows()[idx];
            if (!r) return;
            if (state.selected.has(r.id)) state.selected.delete(r.id);
            else state.selected.add(r.id);
            state.lastClickedIdx = idx;
            renderBody();
        }

        function toggleAll(on) {
            state.selected = on ? new Set(state.items.map(i => i.id)) : new Set();
            renderBody();
        }

        function setTarget(t) { state.target = t; }

        // ══════════════ test ══════════════

        async function test(selectedOnly) {
            if (!state.configName) { Toast.error('Сначала выберите конфиг'); return; }
            if (selectedOnly && !state.selected.size) {
                Toast.error('Ничего не выбрано'); return;
            }
            try {
                const r = await opts.startTest(ctx, selectedOnly);
                if (!r || !r.ok) {
                    Toast.error((r && r.error) || 'не удалось запустить тест');
                    return;
                }
                Toast.info(`Тестируем ${r.count} ${L.testNoun}…`);
                state.testState.running = true;
                state.testState.progress = { phase: 'tcp', done: 0, total: r.count || 0 };
                renderBody();
                pollTest();
            } catch (e) { Toast.error(e.message); }
        }

        function pollTest() {
            if (testTimer) clearTimeout(testTimer);
            testTimer = setTimeout(async () => {
                try {
                    const st = await API.get(opts.testStatusUrl);
                    state.testState.running = !!st.running;
                    if (st.progress) state.testState.progress = st.progress;
                    if (!st.running && st.result && st.result.results) {
                        mergeResults(st.result.results);
                        const sum = st.result.summary || {};
                        const extraMsg = opts.testDoneExtra
                            ? (opts.testDoneExtra(st.result) || '') : '';
                        Toast.success(`Готово: живых ${sum.alive || 0} / ${sum.total || 0}${extraMsg}`);
                        renderBody();
                        return;
                    }
                    renderBody();
                    if (st.running) pollTest();
                } catch (e) {
                    state.testState.running = false; renderBody();
                }
            }, 1000);
        }

        function mergeResults(results) {
            (results || []).forEach(r => {
                state.testResults[r.tag] = {
                    alive: !!r.alive, latency_ms: r.latency_ms,
                    stage: r.stage, error: r.error || '',
                };
            });
        }

        // ══════════════ copy / paste / delete ══════════════

        async function copySelected() {
            if (!state.selected.size) { Toast.error('Ничего не выбрано'); return; }
            try {
                const r = await opts.exportLinks(ctx);
                if (!r || !r.ok || !r.text) { Toast.error(L.noLinks); return; }
                const ok = await copyText(r.text);
                if (ok) Toast.success(`Скопировано ссылок: ${r.count}`);
                else Toast.error('Не удалось записать в буфер — выделите и скопируйте вручную');
            } catch (e) { Toast.error(e.message); }
        }

        async function importText(text) {
            text = (text || '').trim();
            if (!text) return;
            if (!state.configName) { Toast.error('Сначала выберите конфиг'); return; }
            state.busy = true; renderBody();
            try {
                const r = await opts.importLinks(ctx, text);
                if (r && r.ok) {
                    Toast.success(`Добавлено: ${r.added}${r.renamed ? `, переименовано: ${r.renamed}` : ''}${r.errors ? `, ошибок: ${r.errors}` : ''}`);
                    state.showPasteBox = false;
                    await loadItems();
                } else {
                    Toast.error((r && r.error) || 'не удалось импортировать');
                }
            } catch (e) { Toast.error(e.message); }
            finally { state.busy = false; renderBody(); }
        }

        function togglePasteBox() {
            state.showPasteBox = !state.showPasteBox;
            renderBody();
            if (state.showPasteBox) {
                const ta = document.getElementById(`${opts.bodyId}-paste`);
                if (ta) ta.focus();
            }
        }

        function importPasteBox() {
            const ta = document.getElementById(`${opts.bodyId}-paste`);
            importText(ta ? ta.value : '');
        }

        async function deleteSelected() {
            if (!state.selected.size) return;
            const ids = [...state.selected];
            if (!confirm(`Удалить выбранные ${L.itemsAcc} (${ids.length}) из конфига «${state.configName}»?`)) return;
            state.busy = true; renderBody();
            try {
                const r = await opts.deleteItems(ctx, ids);
                if (r && r.ok) {
                    Toast.success(`Удалено: ${(r.deleted || []).length}${(r.skipped || []).length ? `, пропущено: ${r.skipped.length}` : ''}`);
                    state.selected = new Set();
                    await loadItems();
                } else {
                    Toast.error((r && r.error) || 'не удалось удалить');
                }
            } catch (e) { Toast.error(e.message); }
            finally { state.busy = false; renderBody(); }
        }

        // ══════════════ activate ══════════════

        function activateSelected() {
            if (state.selected.size !== 1) {
                Toast.error(`Выберите один ${L.itemOneAcc}`); return;
            }
            activate([...state.selected][0]);
        }

        function activateIdx(idx) {
            const r = sortedRows()[idx];
            if (r) activate(r.id);
        }

        async function activate(id) {
            if (!state.configName) return;
            state.busy = true; renderBody();
            try {
                await opts.activate(ctx, id);
            } catch (e) { Toast.error(e.message); }
            finally { state.busy = false; renderBody(); }
        }

        // ══════════════ hotkeys / clipboard ══════════════

        function attachGlobalHandlers() {
            keyHandler = (e) => {
                // Не мешаем нативным copy/paste/select в полях ввода.
                if (isEditable(e.target)) return;
                const mod = e.ctrlKey || e.metaKey;
                if (mod && (e.key === 'c' || e.key === 'C')) {
                    if (state.selected.size) { e.preventDefault(); copySelected(); }
                } else if (mod && (e.key === 'a' || e.key === 'A')) {
                    if (state.items.length) { e.preventDefault(); toggleAll(true); }
                } else if (e.key === 'Delete') {
                    if (state.selected.size) { e.preventDefault(); deleteSelected(); }
                }
            };
            // Вставка: ловим сам жест — clipboardData доступен без HTTPS.
            pasteHandler = (e) => {
                if (isEditable(e.target)) return;      // пусть пастится в поле
                const text = (e.clipboardData || window.clipboardData)?.getData('text') || '';
                if (text && /(vless|vmess|trojan|ss|hysteria2|hy2|tuic):\/\//i.test(text)) {
                    e.preventDefault();
                    importText(text);
                }
            };
            document.addEventListener('keydown', keyHandler);
            document.addEventListener('paste', pasteHandler);
        }

        function detachGlobalHandlers() {
            if (keyHandler) document.removeEventListener('keydown', keyHandler);
            if (pasteHandler) document.removeEventListener('paste', pasteHandler);
            keyHandler = pasteHandler = null;
        }

        // ══════════════ public API ══════════════

        const api = {
            render, destroy, refreshAll, switchConfig, setTarget,
            sortBy, onRowClick, toggleRow, toggleAll,
            test, copySelected, togglePasteBox, importPasteBox,
            deleteSelected, activate, activateSelected, activateIdx,
        };
        // Движко-специфичные методы адаптера (enableClashApi, toggleDebug…)
        // — оборачиваем, чтобы получали ctx первым аргументом.
        for (const [name, fn] of Object.entries(opts.extraMethods || {})) {
            api[name] = (...args) => fn(ctx, ...args);
        }
        return api;
    }

    return { create, esc, escAttr, humanBytes, copyText };
})();
