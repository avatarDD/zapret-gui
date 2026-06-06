/**
 * singbox_proxies.js — Throne-подобная таблица проксей для sing-box.
 *
 * Единое окно-таблица над outbound'ами выбранного конфига (как главное
 * окно Throne): колонки Имя | Тип | Адрес | Задержка/статус | Трафик ↑/↓.
 *
 *   - выбор строк (клик / Ctrl+клик / Shift-диапазон / чекбоксы);
 *   - сортируемые заголовки: по доступности, задержке, трафику, имени, типу;
 *   - тест выделенных/всех (TCP-отсев + e2e через движок) — переиспользует
 *     /api/singbox/test;
 *   - копирование выделенных в буфер share-ссылками (Ctrl+C) и вставка
 *     серверов из буфера (Ctrl+V) — как Throne copy_links / add_from_clipboard;
 *   - учёт трафика per-proxy через Clash API (опрос /api/singbox/traffic).
 *
 * Хоткеи (когда фокус не в поле ввода): Ctrl/⌘+C, Ctrl/⌘+A, Delete.
 * Вставка ловится событием `paste` (работает и без HTTPS — clipboardData
 * доступен в самом жесте вставки).
 */

const SingboxProxiesPage = (() => {

    let configs = [];
    let configName = '';
    let outbounds = [];                 // только «реальные» серверы
    let testResults = {};               // tag -> {alive, latency_ms, stage, error}
    let traffic = {};                   // tag -> {up, down}
    let clashEnabled = null;            // у конфига настроен clash_api?
    let running = null;

    let selected = new Set();           // выбранные tag'и
    let lastClickedIdx = -1;            // для Shift-диапазона (в отсорт. виде)
    let sortKey = 'avail';
    let sortDir = 'desc';               // desc: лучшие сверху

    let target = 'cloudflare';
    let testState = { running: false, progress: { phase: '', done: 0, total: 0 } };
    let testTimer = null;
    let trafficTimer = null;
    let showPasteBox = false;
    let busy = false;

    // Слушатели на document — снимаем в destroy().
    let keyHandler = null;
    let pasteHandler = null;

    // ══════════════ lifecycle ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Прокси</h1>
                    <p class="page-description">
                        Серверы конфига sing-box: тест доступности и задержки,
                        учёт трафика, копирование/вставка ссылок по Ctrl+C / Ctrl+V.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox-configs'">
                        Конфиги
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SingboxProxiesPage.refreshAll()">
                        Обновить
                    </button>
                </div>
            </div>
            <div id="px-body"></div>
        `;
        attachGlobalHandlers();
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
            const r = await API.get('/api/singbox/configs');
            configs = (r && r.configs) || [];
        } catch (e) { Toast.error(e.message); configs = []; }

        if (!configName || !configs.some(c => c.name === configName)) {
            // По умолчанию — первый «не подписочный», иначе первый.
            const own = configs.find(c => !c.name.startsWith('imported-subscription-'));
            configName = (own || configs[0] || {}).name || '';
        }
        await loadOutbounds();
        await loadTraffic();
        renderBody();
    }

    async function loadOutbounds() {
        outbounds = [];
        if (!configName) return;
        try {
            const r = await API.get(
                `/api/singbox/configs/${encodeURIComponent(configName)}/outbounds`);
            const all = (r && r.outbounds) || [];
            const service = new Set(['direct', 'block', 'dns', 'selector', 'urltest']);
            outbounds = all.filter(o => o && o.tag && o.type && !service.has(o.type));
        } catch (e) { Toast.error(e.message); }
        // Чистим выбор от исчезнувших тегов.
        const present = new Set(outbounds.map(o => o.tag));
        selected = new Set([...selected].filter(t => present.has(t)));
    }

    async function loadTraffic() {
        if (!configName) { traffic = {}; clashEnabled = null; return; }
        try {
            const r = await API.get(
                `/api/singbox/traffic?config=${encodeURIComponent(configName)}`);
            if (r && r.ok) {
                traffic = r.traffic || {};
                clashEnabled = r.clash_api;
                running = r.running;
            }
        } catch (_) { /* трафик не критичен */ }
    }

    function startTrafficPolling() {
        if (trafficTimer) clearTimeout(trafficTimer);
        trafficTimer = setTimeout(async () => {
            const prevClash = clashEnabled;
            await loadTraffic();
            // Не делаем полную перерисовку (она сбросила бы фокус/поле
            // вставки и пересортировала бы строки под рукой) — обновляем
            // только значения трафика на месте. Полный re-render лишь
            // если изменился статус clash_api (появился/исчез баннер).
            if (document.getElementById('px-body')) {
                if (clashEnabled !== prevClash) renderBody();
                else updateTrafficCells();
            }
            startTrafficPolling();
        }, 3000);
    }

    function updateTrafficCells() {
        const body = document.getElementById('px-body');
        if (!body) return;
        body.querySelectorAll('tr[data-tag]').forEach(tr => {
            const cell = tr.querySelector('.px-traffic');
            if (cell) cell.innerHTML = trafficCellHtml(tr.getAttribute('data-tag'));
        });
    }

    async function refreshAll() {
        await loadConfigs();
    }

    function switchConfig(name) {
        configName = name;
        selected = new Set();
        lastClickedIdx = -1;
        testResults = {};
        loadOutbounds().then(loadTraffic).then(renderBody);
    }

    // ══════════════ render ══════════════

    function renderBody() {
        const box = document.getElementById('px-body');
        if (!box) return;

        const cfgOpts = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === configName ? 'selected' : ''}>
                ${escapeHtml(c.name)}${c.name.startsWith('imported-subscription-') ? ' (подписка)' : ''}${c.running ? ' ●' : ''}
            </option>`).join('');

        if (!configs.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Конфигов нет. Создайте конфиг или импортируйте подписку в разделе
                <a href="#singbox-configs" style="text-decoration:underline;">Конфиги</a>,
                либо вставьте ссылки сюда (Ctrl+V).
            </div></div>`;
            return;
        }

        const selCount = selected.size;
        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted" style="margin:0;">Конфиг:</label>
                    <select class="form-input" style="width:auto;"
                            onchange="SingboxProxiesPage.switchConfig(this.value)">
                        ${cfgOpts}
                    </select>
                    <span class="text-muted" style="font-size:12px;">
                        серверов: ${outbounds.length}${selCount ? ` · выбрано: ${selCount}` : ''}
                    </span>
                    <div style="margin-left:auto; display:flex; gap:6px; flex-wrap:wrap;">
                        <label class="text-muted" style="display:flex; align-items:center; gap:4px; font-size:12px;">
                            цель
                            <select class="form-input" style="width:auto;"
                                    onchange="SingboxProxiesPage.setTarget(this.value)">
                                ${['cloudflare', 'amazon', 'google'].map(t =>
                                    `<option value="${t}" ${t === target ? 'selected' : ''}>${t}</option>`).join('')}
                            </select>
                        </label>
                        <button class="btn btn-primary btn-sm" ${testState.running || busy ? 'disabled' : ''}
                                onclick="SingboxProxiesPage.test(false)">
                            ${testState.running ? 'Тест идёт…' : 'Тест всех'}
                        </button>
                        <button class="btn btn-ghost btn-sm" ${testState.running || busy || !selCount ? 'disabled' : ''}
                                onclick="SingboxProxiesPage.test(true)">
                            Тест выделенных
                        </button>
                        <button class="btn btn-ghost btn-sm" ${!selCount ? 'disabled' : ''}
                                onclick="SingboxProxiesPage.copySelected()" title="Ctrl+C">
                            Копировать
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="SingboxProxiesPage.togglePasteBox()" title="Ctrl+V">
                            Вставить
                        </button>
                        <button class="btn btn-ghost btn-sm" ${!selCount || busy ? 'disabled' : ''}
                                onclick="SingboxProxiesPage.deleteSelected()" title="Delete">
                            Удалить
                        </button>
                    </div>
                </div>
                ${renderClashBanner()}
                ${showPasteBox ? renderPasteBox() : ''}
                ${renderTestProgress()}
            </div>

            ${renderTable()}
        `;
    }

    function renderClashBanner() {
        if (clashEnabled !== false) return '';
        return `
            <div class="alert alert-warning" style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                <div style="font-size:12px;">
                    Учёт трафика выключен: у конфига <strong>${escapeHtml(configName)}</strong>
                    нет <code>clash_api</code>. Включите его, чтобы считать объём
                    прокачанного через каждый сервер трафика.
                </div>
                <button class="btn btn-primary btn-sm" ${busy ? 'disabled' : ''}
                        onclick="SingboxProxiesPage.enableClashApi()">
                    Включить учёт трафика
                </button>
            </div>`;
    }

    function renderPasteBox() {
        return `
            <div style="margin-top:10px;">
                <label class="form-label">Вставьте ссылки (vless:// / vmess:// / trojan:// / ss:// / hy2:// / tuic://), по одной в строке:</label>
                <textarea id="px-paste" class="form-textarea" spellcheck="false"
                          style="width:100%; min-height:90px; font-family:monospace; font-size:12px;"
                          placeholder="vless://...&#10;ss://..."></textarea>
                <div style="margin-top:6px; display:flex; gap:6px;">
                    <button class="btn btn-primary btn-sm" onclick="SingboxProxiesPage.importPasteBox()">
                        Импортировать
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SingboxProxiesPage.togglePasteBox()">
                        Отмена
                    </button>
                </div>
            </div>`;
    }

    function renderTestProgress() {
        if (!testState.running) return '';
        const p = testState.progress || { phase: '', done: 0, total: 0 };
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
        if (!outbounds.length) {
            return `<div class="card"><div class="text-muted">
                В конфиге «${escapeHtml(configName)}» нет серверов. Добавьте их в
                «Конструкторе» / «Импорте» или вставьте ссылки (Ctrl+V / кнопка «Вставить»).
            </div></div>`;
        }

        const rows = sortedRows();
        const allSel = rows.length && rows.every(r => selected.has(r.tag));

        const head = (key, label, alignRight) => {
            const active = sortKey === key;
            const arrow = active ? (sortDir === 'desc' ? ' ▼' : ' ▲') : '';
            return `<th style="text-align:${alignRight ? 'right' : 'left'}; cursor:pointer; user-select:none; ${active ? 'color:var(--accent);' : ''}"
                        onclick="SingboxProxiesPage.sortBy('${key}')">${label}${arrow}</th>`;
        };

        const body = rows.map((r, idx) => {
            const sel = selected.has(r.tag);
            return `
                <tr data-tag="${escapeAttr(r.tag)}" style="cursor:pointer; ${sel ? 'background:var(--bg-hover, rgba(120,140,255,.12));' : ''}"
                    onclick="SingboxProxiesPage.onRowClick('${escapeAttr(r.tag)}', ${idx}, event)">
                    <td style="width:28px; text-align:center;">
                        <input type="checkbox" ${sel ? 'checked' : ''}
                               onclick="event.stopPropagation(); SingboxProxiesPage.toggleRow('${escapeAttr(r.tag)}', ${idx})">
                    </td>
                    <td><span style="font-weight:600;">${escapeHtml(r.tag)}</span></td>
                    <td class="text-muted" style="font-size:11px;">${escapeHtml(r.type)}</td>
                    <td class="text-muted" style="font-size:11px;">${escapeHtml(r.address)}</td>
                    <td>${renderTestCell(r.tag)}</td>
                    <td class="px-traffic" style="text-align:right; white-space:nowrap; font-size:12px;">
                        ${trafficCellHtml(r.tag)}
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
                                       onclick="SingboxProxiesPage.toggleAll(this.checked)">
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

    function trafficCellHtml(tag) {
        const tr = traffic[tag] || {};
        const tt = (Number(tr.up) || 0) + (Number(tr.down) || 0);
        if (tt <= 0) return '<span class="text-muted">—</span>';
        return `<span class="text-muted">↑</span> ${humanBytes(tr.up)} `
             + `<span class="text-muted">↓</span> ${humanBytes(tr.down)}`;
    }

    function renderTestCell(tag) {
        const r = testResults[tag];
        if (!r) return '<span class="text-muted">—</span>';
        const dot = r.alive ? '#39c45e' : '#e58';
        if (r.alive) {
            const lat = r.latency_ms != null ? `${r.latency_ms} ms` : 'жив';
            const stage = r.stage === 'e2e' ? 'e2e' : 'tcp';
            return `<span style="color:${dot};">●</span> ${lat}
                    <span class="text-muted" style="font-size:10px;">${stage}</span>`;
        }
        return `<span style="color:${dot};">●</span> <span style="color:#e58;">мёртв</span>
                ${r.error ? `<span class="text-muted" style="font-size:10px;">${escapeHtml(r.error)}</span>` : ''}`;
    }

    // ══════════════ rows / sorting / selection ══════════════

    function rowModel() {
        return outbounds.map(o => ({
            tag: o.tag,
            type: o.type,
            address: (o.server != null ? String(o.server) : '')
                     + (o.server_port != null ? ':' + o.server_port : ''),
        }));
    }

    function sortedRows() {
        const rows = rowModel();
        const dir = sortDir === 'desc' ? -1 : 1;
        const lat = t => {
            const r = testResults[t];
            return (r && r.alive && r.latency_ms != null) ? r.latency_ms : null;
        };
        const aliveRank = t => {
            const r = testResults[t];
            if (!r) return 0;            // не тестировался — посередине
            return r.alive ? 1 : -1;
        };
        const traf = t => {
            const v = traffic[t] || {};
            return (Number(v.up) || 0) + (Number(v.down) || 0);
        };
        const cmp = (a, b) => {
            let x = 0;
            if (sortKey === 'name') x = a.tag.localeCompare(b.tag);
            else if (sortKey === 'type') x = a.type.localeCompare(b.type) || a.tag.localeCompare(b.tag);
            else if (sortKey === 'address') x = a.address.localeCompare(b.address);
            else if (sortKey === 'traffic') x = traf(a.tag) - traf(b.tag);
            else if (sortKey === 'avail') {
                // доступность: сначала по «жив/не тестирован/мёртв», затем
                // по задержке (меньше — лучше, т.е. при desc сверху).
                x = aliveRank(a.tag) - aliveRank(b.tag);
                if (x === 0) {
                    const la = lat(a.tag), lb = lat(b.tag);
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
        if (sortKey === key) {
            sortDir = sortDir === 'desc' ? 'asc' : 'desc';
        } else {
            sortKey = key;
            // Для имени/типа/адреса логичнее по возрастанию, для метрик — убыв.
            sortDir = (key === 'name' || key === 'type' || key === 'address') ? 'asc' : 'desc';
        }
        lastClickedIdx = -1;
        renderBody();
    }

    function onRowClick(tag, idx, event) {
        const rows = sortedRows();
        if (event && event.shiftKey && lastClickedIdx >= 0) {
            const [a, b] = [lastClickedIdx, idx].sort((x, y) => x - y);
            for (let i = a; i <= b && i < rows.length; i++) selected.add(rows[i].tag);
        } else if (event && (event.ctrlKey || event.metaKey)) {
            if (selected.has(tag)) selected.delete(tag); else selected.add(tag);
            lastClickedIdx = idx;
        } else {
            // Обычный клик — выделить только эту строку.
            selected = new Set([tag]);
            lastClickedIdx = idx;
        }
        renderBody();
    }

    function toggleRow(tag, idx) {
        if (selected.has(tag)) selected.delete(tag); else selected.add(tag);
        lastClickedIdx = idx;
        renderBody();
    }

    function toggleAll(on) {
        if (on) selected = new Set(outbounds.map(o => o.tag));
        else selected = new Set();
        renderBody();
    }

    function setTarget(t) { target = t; }

    // ══════════════ test ══════════════

    async function test(selectedOnly) {
        let payload;
        if (selectedOnly) {
            const obs = outbounds.filter(o => selected.has(o.tag));
            if (!obs.length) { Toast.error('Ничего не выбрано'); return; }
            payload = { outbounds: obs, target };
        } else {
            payload = { config: configName, target };
        }
        try {
            const r = await API.post('/api/singbox/test', payload);
            if (!r || !r.ok) { Toast.error((r && r.error) || 'не удалось запустить тест'); return; }
            Toast.info(`Тестируем ${r.count} серверов…`);
            testState.running = true;
            testState.progress = { phase: 'tcp', done: 0, total: r.count || 0 };
            renderBody();
            pollTest();
        } catch (e) { Toast.error(e.message); }
    }

    function pollTest() {
        if (testTimer) clearTimeout(testTimer);
        testTimer = setTimeout(async () => {
            try {
                const st = await API.get('/api/singbox/test/status');
                testState.running = !!st.running;
                if (st.progress) testState.progress = st.progress;
                if (!st.running && st.result && st.result.results) {
                    mergeResults(st.result.results);
                    const sum = st.result.summary || {};
                    Toast.success(`Готово: живых ${sum.alive || 0} / ${sum.total || 0}`);
                    renderBody();
                    return;
                }
                renderBody();
                if (st.running) pollTest();
            } catch (e) {
                testState.running = false; renderBody();
            }
        }, 1000);
    }

    function mergeResults(results) {
        (results || []).forEach(r => {
            testResults[r.tag] = {
                alive: !!r.alive, latency_ms: r.latency_ms,
                stage: r.stage, error: r.error || '',
            };
        });
    }

    // ══════════════ copy / paste / delete ══════════════

    async function copySelected() {
        if (!selected.size) { Toast.error('Ничего не выбрано'); return; }
        const obs = outbounds.filter(o => selected.has(o.tag));
        try {
            const r = await API.post('/api/singbox/export-links', { outbounds: obs });
            if (!r || !r.ok || !r.text) { Toast.error('Нет ссылок для копирования'); return; }
            const ok = await copyText(r.text);
            if (ok) Toast.success(`Скопировано ссылок: ${r.count}`);
            else Toast.error('Не удалось записать в буфер — выделите и скопируйте вручную');
        } catch (e) { Toast.error(e.message); }
    }

    async function importText(text) {
        text = (text || '').trim();
        if (!text) return;
        if (!configName) { Toast.error('Сначала выберите конфиг'); return; }
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(configName)}/import-links`,
                { text });
            if (r && r.ok) {
                Toast.success(`Добавлено: ${r.added}${r.renamed ? `, переименовано: ${r.renamed}` : ''}${r.errors ? `, ошибок: ${r.errors}` : ''}`);
                showPasteBox = false;
                await loadOutbounds();
            } else {
                Toast.error((r && r.error) || 'не удалось импортировать');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    function togglePasteBox() {
        showPasteBox = !showPasteBox;
        renderBody();
        if (showPasteBox) {
            const ta = document.getElementById('px-paste');
            if (ta) ta.focus();
        }
    }

    function importPasteBox() {
        const ta = document.getElementById('px-paste');
        importText(ta ? ta.value : '');
    }

    async function deleteSelected() {
        if (!selected.size) return;
        const tags = [...selected];
        if (!confirm(`Удалить выбранные серверы (${tags.length}) из конфига «${configName}»?`)) return;
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(configName)}/outbounds/delete-bulk`,
                { tags });
            if (r && r.ok) {
                Toast.success(`Удалено: ${(r.deleted || []).length}${(r.skipped || []).length ? `, пропущено: ${r.skipped.length}` : ''}`);
                selected = new Set();
                await loadOutbounds();
            } else {
                Toast.error((r && r.error) || 'не удалось удалить');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    async function enableClashApi() {
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(configName)}/enable-clash-api`);
            if (r && r.ok) {
                if (r.needs_restart) {
                    Toast.success(`clash_api добавлен (порт ${r.port}). Перезапустите конфиг, чтобы учёт заработал.`);
                } else {
                    Toast.success(`clash_api добавлен (порт ${r.port}).`);
                }
                await loadTraffic();
            } else {
                Toast.error((r && r.error) || 'не удалось включить clash_api');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    // ══════════════ hotkeys / clipboard ══════════════

    function isEditable(el) {
        if (!el) return false;
        const tag = (el.tagName || '').toLowerCase();
        return tag === 'input' || tag === 'textarea' || tag === 'select'
               || el.isContentEditable;
    }

    function attachGlobalHandlers() {
        keyHandler = (e) => {
            // Не мешаем нативным copy/paste/select в полях ввода.
            if (isEditable(e.target)) return;
            const mod = e.ctrlKey || e.metaKey;
            if (mod && (e.key === 'c' || e.key === 'C')) {
                if (selected.size) { e.preventDefault(); copySelected(); }
            } else if (mod && (e.key === 'a' || e.key === 'A')) {
                if (outbounds.length) { e.preventDefault(); toggleAll(true); }
            } else if (e.key === 'Delete') {
                if (selected.size) { e.preventDefault(); deleteSelected(); }
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

    // ══════════════ helpers ══════════════

    function humanBytes(n) {
        n = Number(n) || 0;
        if (n < 1024) return n + ' B';
        const u = ['KB', 'MB', 'GB', 'TB']; let i = -1;
        do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
        return (n < 10 ? n.toFixed(2) : n.toFixed(1)) + ' ' + u[i];
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escapeAttr(s) {
        return escapeHtml(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    return {
        render, destroy, refreshAll, switchConfig, setTarget,
        sortBy, onRowClick, toggleRow, toggleAll,
        test, copySelected, togglePasteBox, importPasteBox,
        deleteSelected, enableClashApi,
    };
})();
