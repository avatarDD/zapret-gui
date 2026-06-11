/**
 * mihomo_proxies.js — таблица проксей mihomo (паритет с singbox_proxies.js).
 *
 * Единое окно-таблица над секцией `proxies` выбранного clash-конфига:
 * Имя | Тип | Адрес | Задержка/статус | Трафик ↑/↓.
 *
 *   - выбор строк (клик / Ctrl+клик / Shift-диапазон / чекбоксы);
 *   - сортируемые заголовки (доступность/задержка/трафик/имя/тип);
 *   - тест выделенных/всех (TCP-отсев + e2e через движок mihomo);
 *   - copy/paste share-ссылок (Ctrl+C / Ctrl+V);
 *   - активация выбранного — живое переключение через external-controller;
 *   - учёт трафика per-proxy (Clash API /connections);
 *   - режим отладки (log-level=debug) + просмотр лога инстанса.
 *
 * Отличия от sing-box: tag = имя прокси (может содержать пробелы/эмодзи),
 * поэтому обработчики строк используют индекс, а не имя в inline-onclick.
 * Переключение/трафик/тест требуют запущенного инстанса с external-
 * controller — у mihomo выбор узла живёт в рантайме, не в YAML.
 */

const MihomoProxiesPage = (() => {

    let configs = [];
    let configName = '';
    let proxies = [];                   // [{name,type,server,port}]
    let activeName = '';                // активный узел (now первой select-группы)
    let running = false;
    let hasController = false;          // в конфиге есть external-controller
    let controllerLive = false;         // controller отвечает
    let selectGroups = [];

    let testResults = {};               // name -> {alive, latency_ms, stage, error}
    let traffic = {};                   // name -> {up, down}

    let selected = new Set();           // выбранные имена
    let lastClickedIdx = -1;
    let sortKey = 'avail';
    let sortDir = 'desc';

    let target = 'cloudflare';
    let testState = { running: false, progress: { phase: '', done: 0, total: 0 } };
    let testTimer = null;
    let trafficTimer = null;
    let showPasteBox = false;
    let busy = false;
    let debugEnabled = false;
    let logText = null;                 // строка лога или null (панель скрыта)

    let keyHandler = null;
    let pasteHandler = null;

    // ══════════════ lifecycle ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Прокси mihomo</h1>
                    <p class="page-description">
                        Серверы clash-конфига: тест задержки через движок,
                        учёт трафика, переключение активного узла на лету,
                        copy/paste ссылок (Ctrl+C / Ctrl+V).
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='mihomo'">
                        Инстансы
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoProxiesPage.refreshAll()">
                        Обновить
                    </button>
                </div>
            </div>
            <div id="mpx-body"></div>
        `;
        attachGlobalHandlers();
        loadDebug();
        loadConfigs();
        startTrafficPolling();
    }

    function destroy() {
        if (testTimer) { clearTimeout(testTimer); testTimer = null; }
        if (trafficTimer) { clearTimeout(trafficTimer); trafficTimer = null; }
        detachGlobalHandlers();
    }

    // ══════════════ data ══════════════

    async function loadDebug() {
        try {
            const r = await API.get('/api/mihomo/debug');
            debugEnabled = !!(r && r.enabled);
        } catch (_) { /* не критично */ }
    }

    async function loadConfigs() {
        try {
            const r = await API.get('/api/mihomo/configs');
            configs = (r && r.configs) || [];
        } catch (e) { Toast.error(e.message); configs = []; }

        if (!configName || !configs.some(c => c.name === configName)) {
            configName = (configs[0] || {}).name || '';
        }
        await loadProxies();
        await loadTraffic();
        renderBody();
    }

    async function loadProxies() {
        proxies = []; activeName = ''; running = false;
        hasController = false; controllerLive = false; selectGroups = [];
        if (!configName) return;
        try {
            const r = await API.get(
                `/api/mihomo/configs/${encodeURIComponent(configName)}/proxies`);
            if (r && r.ok) {
                proxies = r.proxies || [];
                activeName = r.active || '';
                running = !!r.running;
                hasController = !!r.controller;
                controllerLive = !!r.controller_live;
                selectGroups = r.select_groups || [];
            } else {
                Toast.error((r && r.error) || 'не удалось получить прокси');
            }
        } catch (e) { Toast.error(e.message); }
        // Чистим выбор от исчезнувших имён.
        const present = new Set(proxies.map(p => p.name));
        selected = new Set([...selected].filter(n => present.has(n)));
    }

    async function loadTraffic() {
        if (!configName) { traffic = {}; return; }
        try {
            const r = await API.get(
                `/api/mihomo/traffic?config=${encodeURIComponent(configName)}`);
            if (r && r.ok) traffic = r.traffic || {};
        } catch (_) { /* трафик не критичен */ }
    }

    function startTrafficPolling() {
        if (trafficTimer) clearTimeout(trafficTimer);
        trafficTimer = setTimeout(async () => {
            await loadTraffic();
            if (document.getElementById('mpx-body')) updateTrafficCells();
            startTrafficPolling();
        }, 3000);
    }

    function updateTrafficCells() {
        const body = document.getElementById('mpx-body');
        if (!body) return;
        body.querySelectorAll('tr[data-name]').forEach(tr => {
            const cell = tr.querySelector('.mpx-traffic');
            if (cell) cell.innerHTML = trafficCellHtml(tr.getAttribute('data-name'));
        });
    }

    async function refreshAll() { await loadConfigs(); }

    function switchConfig(name) {
        configName = name;
        selected = new Set();
        lastClickedIdx = -1;
        testResults = {};
        logText = null;
        loadProxies().then(loadTraffic).then(renderBody);
    }

    // ══════════════ render ══════════════

    function renderBody() {
        const box = document.getElementById('mpx-body');
        if (!box) return;

        if (!configs.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Конфигов нет. Создайте конфиг на странице
                <a href="#mihomo" style="text-decoration:underline;">Инстансы</a>
                и вставьте clash-YAML, либо вставьте ссылки сюда (Ctrl+V).
            </div></div>`;
            return;
        }

        const cfgOpts = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === configName ? 'selected' : ''}>
                ${escapeHtml(c.name)}${c.running ? ' ●' : ''}
            </option>`).join('');

        const selCount = selected.size;
        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted" style="margin:0;">Конфиг:</label>
                    <select class="form-input" style="width:auto;"
                            onchange="MihomoProxiesPage.switchConfig(this.value)">
                        ${cfgOpts}
                    </select>
                    <span class="text-muted" style="font-size:12px;">
                        прокси: ${proxies.length}${selCount ? ` · выбрано: ${selCount}` : ''}
                        ${running ? ' · <span style="color:#39c45e;">running</span>'
                                  : ' · <span style="color:#e58;">stopped</span>'}
                    </span>
                    <div style="margin-left:auto; display:flex; gap:6px; flex-wrap:wrap;">
                        <label class="text-muted" style="display:flex; align-items:center; gap:4px; font-size:12px;">
                            цель
                            <select class="form-input" style="width:auto;"
                                    onchange="MihomoProxiesPage.setTarget(this.value)">
                                ${['cloudflare', 'amazon', 'google'].map(t =>
                                    `<option value="${t}" ${t === target ? 'selected' : ''}>${t}</option>`).join('')}
                            </select>
                        </label>
                        <button class="btn btn-primary btn-sm" ${testState.running || busy ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.test(false)">
                            ${testState.running ? 'Тест идёт…' : 'Тест всех'}
                        </button>
                        <button class="btn btn-ghost btn-sm" ${testState.running || busy || !selCount ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.test(true)">
                            Тест выделенных
                        </button>
                        <button class="btn btn-primary btn-sm" ${busy || selCount !== 1 ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.activateSelected()"
                                title="Пустить трафик через выделенный узел (двойной клик по строке)">
                            ▶ Через эту
                        </button>
                        <button class="btn btn-ghost btn-sm" ${!selCount ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.copySelected()" title="Ctrl+C">
                            Копировать
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="MihomoProxiesPage.togglePasteBox()" title="Ctrl+V">
                            Вставить
                        </button>
                        <button class="btn btn-ghost btn-sm" ${!selCount || busy ? 'disabled' : ''}
                                onclick="MihomoProxiesPage.deleteSelected()" title="Delete">
                            Удалить
                        </button>
                    </div>
                </div>
                <div style="display:flex; gap:14px; align-items:center; flex-wrap:wrap; margin-top:10px;">
                    <label class="text-muted" style="display:flex; align-items:center; gap:5px; font-size:12px;">
                        <input type="checkbox" ${debugEnabled ? 'checked' : ''}
                               onchange="MihomoProxiesPage.toggleDebug(this.checked)">
                        режим отладки (log-level=debug)
                    </label>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoProxiesPage.toggleLog()">
                        ${logText !== null ? 'Скрыть лог' : 'Показать лог'}
                    </button>
                </div>
                ${renderControllerBanner()}
                ${showPasteBox ? renderPasteBox() : ''}
                ${renderTestProgress()}
                ${logText !== null ? renderLogPanel() : ''}
            </div>

            ${renderTable()}
        `;
    }

    function renderControllerBanner() {
        if (hasController && (controllerLive || !running)) return '';
        if (!hasController) {
            return `
                <div class="alert alert-warning" style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                    <div style="font-size:12px;">
                        У конфига <strong>${escapeHtml(configName)}</strong> нет
                        <code>external-controller</code> — без него недоступны учёт
                        трафика, тест через движок и переключение узла на лету.
                    </div>
                    <button class="btn btn-primary btn-sm" ${busy ? 'disabled' : ''}
                            onclick="MihomoProxiesPage.enableController()">
                        Включить управление и учёт трафика
                    </button>
                </div>`;
        }
        // есть controller, но running и не отвечает
        return `
            <div class="alert alert-warning" style="margin-top:10px; font-size:12px;">
                external-controller настроен, но не отвечает. Проверьте порт/secret
                и что конфиг перезапущен после изменения.
            </div>`;
    }

    function renderPasteBox() {
        return `
            <div style="margin-top:10px;">
                <label class="form-label">Вставьте ссылки (vless:// / vmess:// / trojan:// / ss:// / hy2:// / tuic://), по одной в строке:</label>
                <textarea id="mpx-paste" class="form-textarea" spellcheck="false"
                          style="width:100%; min-height:90px; font-family:monospace; font-size:12px;"
                          placeholder="vless://...&#10;ss://..."></textarea>
                <div style="margin-top:6px; display:flex; gap:6px;">
                    <button class="btn btn-primary btn-sm" onclick="MihomoProxiesPage.importPasteBox()">
                        Импортировать
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoProxiesPage.togglePasteBox()">
                        Отмена
                    </button>
                </div>
            </div>`;
    }

    function renderLogPanel() {
        return `
            <div style="margin-top:12px;">
                <div class="text-muted" style="font-size:11px; margin-bottom:4px;">
                    Лог инстанса «${escapeHtml(configName)}» (хвост):
                </div>
                <pre style="max-height:240px; overflow:auto; background:var(--bg-input);
                            padding:8px; border-radius:6px; font-size:11px; white-space:pre-wrap;
                            margin:0;">${escapeHtml(logText || '(пусто)')}</pre>
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
        if (!proxies.length) {
            return `<div class="card"><div class="text-muted">
                В конфиге «${escapeHtml(configName)}» нет прокси. Вставьте ссылки
                (Ctrl+V / кнопка «Вставить») или добавьте их в YAML на странице
                «Инстансы».
            </div></div>`;
        }

        const rows = sortedRows();
        const allSel = rows.length && rows.every(r => selected.has(r.name));

        const head = (key, label, alignRight) => {
            const active = sortKey === key;
            const arrow = active ? (sortDir === 'desc' ? ' ▼' : ' ▲') : '';
            return `<th style="text-align:${alignRight ? 'right' : 'left'}; cursor:pointer; user-select:none; ${active ? 'color:var(--accent);' : ''}"
                        onclick="MihomoProxiesPage.sortBy('${key}')">${label}${arrow}</th>`;
        };

        const body = rows.map((r, idx) => {
            const sel = selected.has(r.name);
            const isActive = r.name === activeName;
            return `
                <tr data-name="${escapeAttr(r.name)}" style="cursor:pointer; ${sel ? 'background:var(--bg-hover, rgba(120,140,255,.12));' : ''}"
                    title="Двойной клик — пустить трафик через этот узел"
                    onclick="MihomoProxiesPage.onRowClick(${idx}, event)"
                    ondblclick="MihomoProxiesPage.activateIdx(${idx})">
                    <td style="width:28px; text-align:center;">
                        <input type="checkbox" ${sel ? 'checked' : ''}
                               onclick="event.stopPropagation(); MihomoProxiesPage.toggleRow(${idx})">
                    </td>
                    <td>
                        ${isActive ? '<span style="color:#39c45e;" title="активный узел">▶</span> ' : ''}
                        <span style="font-weight:600;">${escapeHtml(r.name)}</span>
                    </td>
                    <td class="text-muted" style="font-size:11px;">${escapeHtml(r.type)}</td>
                    <td class="text-muted" style="font-size:11px;">${escapeHtml(addressOf(r))}</td>
                    <td>${renderTestCell(r.name)}</td>
                    <td class="mpx-traffic" style="text-align:right; white-space:nowrap; font-size:12px;">
                        ${trafficCellHtml(r.name)}
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
                                       onclick="MihomoProxiesPage.toggleAll(this.checked)">
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

    function addressOf(r) {
        return (r.server != null ? String(r.server) : '')
             + (r.port != null && r.port !== '' ? ':' + r.port : '');
    }

    function trafficCellHtml(name) {
        const tr = traffic[name] || {};
        const tt = (Number(tr.up) || 0) + (Number(tr.down) || 0);
        if (tt <= 0) return '<span class="text-muted">—</span>';
        return `<span class="text-muted">↑</span> ${humanBytes(tr.up)} `
             + `<span class="text-muted">↓</span> ${humanBytes(tr.down)}`;
    }

    function renderTestCell(name) {
        const r = testResults[name];
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

    function sortedRows() {
        const rows = proxies.slice();
        const dir = sortDir === 'desc' ? -1 : 1;
        const lat = n => {
            const r = testResults[n];
            return (r && r.alive && r.latency_ms != null) ? r.latency_ms : null;
        };
        const aliveRank = n => {
            const r = testResults[n];
            if (!r) return 0;
            return r.alive ? 1 : -1;
        };
        const traf = n => {
            const v = traffic[n] || {};
            return (Number(v.up) || 0) + (Number(v.down) || 0);
        };
        const cmp = (a, b) => {
            let x = 0;
            if (sortKey === 'name') x = String(a.name).localeCompare(String(b.name));
            else if (sortKey === 'type') x = String(a.type).localeCompare(String(b.type)) || String(a.name).localeCompare(String(b.name));
            else if (sortKey === 'address') x = addressOf(a).localeCompare(addressOf(b));
            else if (sortKey === 'traffic') x = traf(a.name) - traf(b.name);
            else if (sortKey === 'avail') {
                x = aliveRank(a.name) - aliveRank(b.name);
                if (x === 0) {
                    const la = lat(a.name), lb = lat(b.name);
                    if (la == null && lb == null) x = 0;
                    else if (la == null) x = -1;
                    else if (lb == null) x = 1;
                    else x = lb - la;
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
            sortDir = (key === 'name' || key === 'type' || key === 'address') ? 'asc' : 'desc';
        }
        lastClickedIdx = -1;
        renderBody();
    }

    function onRowClick(idx, event) {
        const rows = sortedRows();
        const r = rows[idx];
        if (!r) return;
        if (event && event.shiftKey && lastClickedIdx >= 0) {
            const [a, b] = [lastClickedIdx, idx].sort((x, y) => x - y);
            for (let i = a; i <= b && i < rows.length; i++) selected.add(rows[i].name);
        } else if (event && (event.ctrlKey || event.metaKey)) {
            if (selected.has(r.name)) selected.delete(r.name); else selected.add(r.name);
            lastClickedIdx = idx;
        } else {
            selected = new Set([r.name]);
            lastClickedIdx = idx;
        }
        renderBody();
    }

    function toggleRow(idx) {
        const r = sortedRows()[idx];
        if (!r) return;
        if (selected.has(r.name)) selected.delete(r.name); else selected.add(r.name);
        lastClickedIdx = idx;
        renderBody();
    }

    function toggleAll(on) {
        selected = on ? new Set(proxies.map(p => p.name)) : new Set();
        renderBody();
    }

    function setTarget(t) { target = t; }

    // ══════════════ test ══════════════

    async function test(selectedOnly) {
        if (!configName) { Toast.error('Сначала выберите конфиг'); return; }
        const payload = { config: configName, target };
        if (selectedOnly) {
            if (!selected.size) { Toast.error('Ничего не выбрано'); return; }
            payload.names = [...selected];
        }
        try {
            const r = await API.post('/api/mihomo/test', payload);
            if (!r || !r.ok) { Toast.error((r && r.error) || 'не удалось запустить тест'); return; }
            Toast.info(`Тестируем ${r.count} прокси…`);
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
                const st = await API.get('/api/mihomo/test/status');
                testState.running = !!st.running;
                if (st.progress) testState.progress = st.progress;
                if (!st.running && st.result && st.result.results) {
                    mergeResults(st.result.results);
                    const sum = st.result.summary || {};
                    const eng = st.result.engine_used ? '' : ' (только TCP — запустите конфиг для теста через движок)';
                    Toast.success(`Готово: живых ${sum.alive || 0} / ${sum.total || 0}${eng}`);
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
        try {
            const r = await API.post('/api/mihomo/export-links',
                { config: configName, names: [...selected] });
            if (!r || !r.ok || !r.text) { Toast.error('Нет ссылок для копирования (тип не экспортируется)'); return; }
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
                `/api/mihomo/configs/${encodeURIComponent(configName)}/import-links`,
                { text });
            if (r && r.ok) {
                Toast.success(`Добавлено: ${r.added}${r.renamed ? `, переименовано: ${r.renamed}` : ''}${r.errors ? `, ошибок: ${r.errors}` : ''}`);
                showPasteBox = false;
                await loadProxies();
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
            const ta = document.getElementById('mpx-paste');
            if (ta) ta.focus();
        }
    }

    function importPasteBox() {
        const ta = document.getElementById('mpx-paste');
        importText(ta ? ta.value : '');
    }

    async function deleteSelected() {
        if (!selected.size) return;
        const names = [...selected];
        if (!confirm(`Удалить выбранные прокси (${names.length}) из конфига «${configName}»?`)) return;
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/mihomo/configs/${encodeURIComponent(configName)}/proxies/delete-bulk`,
                { names });
            if (r && r.ok) {
                Toast.success(`Удалено: ${(r.deleted || []).length}${(r.skipped || []).length ? `, пропущено: ${r.skipped.length}` : ''}`);
                selected = new Set();
                await loadProxies();
            } else if (r && r.needs_pyyaml) {
                Toast.error(r.error || 'для удаления нужен PyYAML');
            } else {
                Toast.error((r && r.error) || 'не удалось удалить');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    // ══════════════ activate ══════════════

    function activateSelected() {
        if (selected.size !== 1) { Toast.error('Выберите один узел'); return; }
        activate([...selected][0]);
    }

    function activateIdx(idx) {
        const r = sortedRows()[idx];
        if (r) activate(r.name);
    }

    async function activate(name) {
        if (!configName) return;
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/mihomo/configs/${encodeURIComponent(configName)}/activate`,
                { name });
            if (r && r.ok) {
                Toast.success(`Трафик идёт через «${name}» (группа ${r.group || '?'})`);
                await loadProxies();
            } else if (r && r.needs_running) {
                Toast.error('Запустите конфиг — переключение у mihomo делается на лету.');
            } else if (r && r.needs_controller) {
                Toast.error('Нет external-controller — включите управление кнопкой и перезапустите конфиг.');
            } else {
                Toast.error((r && r.error) || 'не удалось переключить');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    async function enableController() {
        busy = true; renderBody();
        try {
            const r = await API.post(
                `/api/mihomo/configs/${encodeURIComponent(configName)}/enable-controller`);
            if (r && r.ok) {
                if (r.needs_restart) {
                    Toast.success(`external-controller добавлен (порт ${r.port}). Перезапустите конфиг, чтобы заработало.`);
                } else {
                    Toast.success(`external-controller добавлен (порт ${r.port}).`);
                }
                await loadProxies();
            } else {
                Toast.error((r && r.error) || 'не удалось включить');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderBody(); }
    }

    // ══════════════ debug / log ══════════════

    async function toggleDebug(on) {
        try {
            const r = await API.post('/api/mihomo/debug', { enabled: on });
            if (r && r.ok) {
                debugEnabled = !!r.enabled;
                Toast.success(`Режим отладки ${debugEnabled ? 'включён' : 'выключен'} — применится при перезапуске инстанса`);
            } else {
                Toast.error((r && r.error) || 'не удалось');
            }
        } catch (e) { Toast.error(e.message); }
        finally { renderBody(); }
    }

    async function toggleLog() {
        if (logText !== null) { logText = null; renderBody(); return; }
        if (!configName) { Toast.error('Сначала выберите конфиг'); return; }
        try {
            const r = await API.get(
                `/api/mihomo/configs/${encodeURIComponent(configName)}/log?lines=200`);
            if (r && r.ok) {
                logText = r.exists ? (r.log || '(пусто)') : '(лог ещё не создан — запустите конфиг)';
            } else {
                logText = (r && r.error) || '(ошибка чтения лога)';
            }
        } catch (e) { logText = e.message; }
        renderBody();
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
            if (isEditable(e.target)) return;
            const mod = e.ctrlKey || e.metaKey;
            if (mod && (e.key === 'c' || e.key === 'C')) {
                if (selected.size) { e.preventDefault(); copySelected(); }
            } else if (mod && (e.key === 'a' || e.key === 'A')) {
                if (proxies.length) { e.preventDefault(); toggleAll(true); }
            } else if (e.key === 'Delete') {
                if (selected.size) { e.preventDefault(); deleteSelected(); }
            }
        };
        pasteHandler = (e) => {
            if (isEditable(e.target)) return;
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
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (_) { /* fallback ниже */ }
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
        deleteSelected, activate, activateSelected, activateIdx,
        enableController, toggleDebug, toggleLog,
    };
})();
