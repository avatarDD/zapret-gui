/**
 * lists.js — страница «Списки».
 *
 * Именованные списки доменов/CIDR (core/named_lists), общие для
 * nfqws2-hostlist'ов и единого слоя маршрутизации. CRUD + импорт текстом.
 */

const ListsPage = (() => {

    let lists = [];
    let editing = null;   // {id?, name, description, text, isNew,
                          //  sourceUrl?, intervalHours?}
    let curated = { presets: [], refresher: {}, transport: '' };
    let curatedUrl = '';
    let curatedInterval = 12;   // интервал (часы) для добавляемого URL
    let transports = null;      // /api/install/transports (через TransportSelect)
    let busy = false;
    let interfaces = [];      // из /api/routing/interfaces (туннели)
    let routeFor = null;      // {listId, listName} — открыт пикер «в маршрут»
    let _eventAbort = null;

    function _bindEvents(container) {
        if (_eventAbort) _eventAbort.abort();
        _eventAbort = new AbortController();
        const signal = _eventAbort.signal;

        container.addEventListener('click', e => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            const action = btn.dataset.action;
            switch (action) {
                case 'new-list': newList(); break;
                case 'refresh-all-managed': refreshAllManaged(); break;
                case 'refresh': refresh(); break;
                case 'add-preset': addPreset(btn.dataset.url); break;
                case 'add-preset-to-route': addPresetToRoute(btn.dataset.url, btn.dataset.name); break;
                case 'add-custom-url': addCustomUrl(); break;
                case 'refresh-list': refreshList(btn.dataset.id); break;
                case 'open-route': openRoute(btn.dataset.id, btn.dataset.name); break;
                case 'edit': edit(btn.dataset.id); break;
                case 'del': del(btn.dataset.id); break;
                case 'close-editor': closeEditor(); break;
                case 'save': save(); break;
                case 'close-route': closeRoute(); break;
                case 'create-route': createRoute(); break;
            }
        }, { signal });

        container.addEventListener('input', e => {
            const action = e.target.dataset.action;
            if (!action) return;
            switch (action) {
                case 'curated-url-input': onCuratedUrl(e.target.value); break;
            }
        }, { signal });

        container.addEventListener('change', e => {
            const action = e.target.dataset.action;
            if (!action) return;
            switch (action) {
                case 'curated-interval-change': onCuratedInterval(e.target.value); break;
                case 'set-transport': setTransport(e.target.value); break;
            }
        }, { signal });
    }

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Списки маршрутизации${typeof Help !== 'undefined' ? Help.button('lists') : ''}</h1>
                    <p class="page-description">
                        Именованные списки доменов и IP/CIDR. Используются
                        в «Маршрутизации» (назначение → метод) и как
                        hostlist'ы nfqws2.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" data-action="new-list">+ Список</button>
                    <button class="btn btn-ghost btn-sm" data-action="refresh-all-managed">↻ Обновить списки</button>
                    <button class="btn btn-ghost btn-sm" data-action="refresh">Обновить</button>
                </div>
            </div>
            <div id="lists-curated"></div>
            <div id="lists-route"></div>
            <div id="lists-editor"></div>
            <div id="lists-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
        `;
        _bindEvents(container);
        refresh();
    }
    function destroy() {}

    async function refresh() {
        try {
            const [r, c, ifc, tr] = await Promise.all([
                API.get('/api/lists'),
                API.get('/api/lists/curated').catch(() => null),
                API.get('/api/routing/interfaces').catch(() => null),
                TransportSelect.load().catch(() => null),
            ]);
            lists = (r && r.lists) || [];
            if (c && c.ok) curated = { presets: c.presets || [],
                                       refresher: c.refresher || {},
                                       transport: c.transport || '' };
            interfaces = (ifc && ifc.interfaces) || [];
            if (tr) transports = tr;
        } catch (e) { Toast.error(e.message); lists = []; }
        renderCurated();
        renderRoutePicker();
        renderEditor();
        renderBody();
    }

    function renderCurated() {
        const box = document.getElementById('lists-curated');
        if (!box) return;

        // Группировка пресетов по category
        const groups = {};
        const CATEGORY_LABELS = {
            services: 'Сервисы',
            countries: 'Страны',
            categories: 'Категории',
        };
        for (const p of (curated.presets || [])) {
            const cat = p.category || 'other';
            if (!groups[cat]) groups[cat] = [];
            groups[cat].push(p);
        }

        // Порядок групп
        const groupOrder = ['services', 'countries', 'categories', 'other'];
        let groupsHtml = '';
        for (const cat of groupOrder) {
            const items = groups[cat];
            if (!items || !items.length) continue;
            const label = CATEGORY_LABELS[cat] || cat;
            const chips = items.map(p => `
                <span class="preset-chip" style="display:inline-flex;gap:2px;">
                    <button class="btn btn-ghost btn-sm" ${p.added||busy?'disabled':''}
                            title="${escAttr(p.description||p.url)}"
                            data-action="add-preset" data-url="${escAttr(p.url)}">
                        ${p.added ? '✓ ' : '+ '}${esc(p.name)}
                    </button>
                    ${p.added ? `<button class="btn btn-ghost btn-sm" title="Добавить в маршрут"
                            data-action="add-preset-to-route" data-url="${escAttr(p.url)}" data-name="${escAttr(p.name)}"
                            style="font-size:10px; padding:2px 6px;">→</button>` : ''}
                </span>`).join(' ');
            groupsHtml += `
                <div style="margin-bottom:8px;">
                    <div style="font-size:11px; font-weight:600; color:var(--text-muted);
                                text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">
                        ${esc(label)}
                    </div>
                    <div style="display:flex; flex-wrap:wrap; gap:6px;">${chips}</div>
                </div>`;
        }

        box.innerHTML = `
            <div class="card" style="margin-bottom:16px;">
                <div class="card-title">Готовые списки (podkop-стиль)</div>
                <p class="text-muted" style="font-size:12px; margin:4px 0 8px;">
                    Community-списки доменов с автообновлением по таймеру
                    (источник: itdoginfo/allow-domains). Добавьте одним кликом,
                    затем используйте в «Маршрутизации». Ручные правки при
                    обновлении сохраняются; пустой ответ сервера не затирает
                    текущее содержимое.
                </p>
                ${groupsHtml}
                <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap; align-items:center;">
                    <input id="lst-curated-url" class="form-control" style="flex:1; min-width:220px;"
                           placeholder="Свой URL списка доменов (raw .txt/.lst)"
                           value="${escAttr(curatedUrl)}"
                           data-action="curated-url-input">
                    <input id="lst-curated-interval" type="number" min="1" step="1"
                           class="form-control" style="width:80px;"
                           title="Интервал автообновления, часов"
                           value="${curatedInterval}"
                           data-action="curated-interval-change">
                    <span class="text-muted" style="font-size:11px;">ч</span>
                    <button class="btn btn-primary btn-sm" ${busy?'disabled':''}
                            data-action="add-custom-url">Добавить URL</button>
                </div>
                <div style="display:flex; gap:8px; margin-top:10px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted" style="font-size:12px;">Качать через:</label>
                    <select class="form-control" style="max-width:300px;"
                            data-action="set-transport">
                        ${TransportSelect.optionsHtml(transports, curated.transport)}
                    </select>
                    <span class="text-muted" style="font-size:11px;">
                        для автообновления всех списков с URL; «напрямую»
                        учитывает зеркало из Настройки → Установка
                    </span>
                </div>
            </div>`;
    }

    function renderBody() {
        const box = document.getElementById('lists-body');
        if (!box) return;
        if (!lists.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Списков нет. Нажмите «+ Список».</div></div>`;
            return;
        }
        box.innerHTML = `<div class="card"><table class="table">
            <thead><tr><th>Имя</th><th>Домены</th><th>CIDR</th>
                <th>Описание</th><th style="width:160px;"></th></tr></thead>
            <tbody>${lists.map(l => {
                const managed = !!(l.source_url && String(l.source_url).trim());
                let badge = '';
                if (managed) {
                    const st = l.last_status;
                    const color = st === 'ok' ? '#39c45e'
                        : (st === 'error' ? '#e58'
                           : (st === 'empty' ? '#e5a' : '#888'));
                    const when = l.last_refresh
                        ? new Date(l.last_refresh * 1000).toLocaleString() : 'никогда';
                    badge = `<div class="text-muted" style="font-size:10px;">
                        <span style="color:${color};">●</span> авто ·
                        каждые ${parseInt(l.interval_hours, 10) || 12} ч ·
                        обновлён: ${esc(when)}
                        ${l.last_error ? ' · ' + esc(l.last_error) : ''}</div>`;
                }
                return `
                <tr>
                    <td><strong>${esc(l.name)}</strong>${badge}</td>
                    <td>${l.domain_count}</td>
                    <td>${l.cidr_count}</td>
                    <td>${esc(l.description || '')}</td>
                    <td style="text-align:right;">
                        ${managed ? `<button class="btn btn-ghost btn-sm" title="Обновить из источника"
                            data-action="refresh-list" data-id="${esc(l.id)}">↻</button>` : ''}
                        <button class="btn btn-ghost btn-sm" title="Создать маршрут для этого списка"
                            data-action="open-route" data-id="${esc(l.id)}" data-name="${escAttr(l.name)}">→ Маршрут</button>
                        <button class="btn btn-ghost btn-sm" data-action="edit" data-id="${esc(l.id)}">Ред.</button>
                        <button class="btn btn-ghost btn-sm" data-action="del" data-id="${esc(l.id)}">✕</button>
                    </td>
                </tr>`; }).join('')}
            </tbody></table></div>`;
    }

    function renderEditor() {
        const box = document.getElementById('lists-editor');
        if (!box) return;
        if (!editing) { box.innerHTML = ''; return; }
        box.innerHTML = `
            <div class="card" style="margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between;">
                    <div class="card-title">${editing.isNew ? 'Новый список' : 'Редактирование'}</div>
                    <button class="btn btn-ghost btn-sm" data-action="close-editor">Закрыть</button>
                </div>
                <div style="display:grid; grid-template-columns:120px 1fr; gap:8px 12px; margin-top:8px;">
                    <label class="text-muted" style="padding-top:6px;">Имя</label>
                    <input id="lst-name" class="form-control" style="max-width:320px;"
                           value="${escAttr(editing.name)}">
                    <label class="text-muted" style="padding-top:6px;">Описание</label>
                    <input id="lst-desc" class="form-control" style="max-width:480px;"
                           value="${escAttr(editing.description)}">
                    ${editing.sourceUrl ? `
                    <label class="text-muted" style="padding-top:6px;">Автообновление</label>
                    <div style="display:flex; gap:6px; align-items:center;">
                        <span class="text-muted" style="font-size:12px;">каждые</span>
                        <input id="lst-interval" type="number" min="1" step="1"
                               class="form-control" style="width:80px;"
                               value="${parseInt(editing.intervalHours, 10) || 12}">
                        <span class="text-muted" style="font-size:12px;">ч ·
                            источник: <span style="word-break:break-all;">${esc(editing.sourceUrl)}</span>
                        </span>
                    </div>` : ''}
                    <label class="text-muted" style="padding-top:6px;">Записи</label>
                    <textarea id="lst-text" spellcheck="false"
                              placeholder="Домены и/или CIDR, по одному в строке или через запятую"
                              style="width:100%; min-height:220px; font-family:monospace; font-size:12px;">${esc(editing.text)}</textarea>
                </div>
                <div style="margin-top:10px;">
                    <button class="btn btn-primary btn-sm" data-action="save">Сохранить</button>
                </div>
            </div>`;
    }

    function newList() {
        editing = { name: '', description: '', text: '', isNew: true };
        renderEditor();
    }

    async function edit(id) {
        try {
            const r = await API.get('/api/lists/' + encodeURIComponent(id));
            if (!r || !r.ok) { Toast.error('не найден'); return; }
            const l = r.list;
            const text = [].concat(l.domains || [], l.cidrs || []).join('\n');
            editing = { id, name: l.name, description: l.description || '',
                        text, isNew: false,
                        sourceUrl: (l.source_url || '').trim(),
                        intervalHours: l.interval_hours };
            renderEditor();
        } catch (e) { Toast.error(e.message); }
    }

    function closeEditor() { editing = null; renderEditor(); }

    async function save() {
        const name = (document.getElementById('lst-name').value || '').trim();
        const description = document.getElementById('lst-desc').value || '';
        const entries = document.getElementById('lst-text').value || '';
        if (!name) { Toast.error('Укажите имя'); return; }
        try {
            let r;
            if (editing.isNew) {
                r = await API.post('/api/lists', { name, description, entries });
            } else {
                const body = { name, description, entries, replace: true };
                const intervalEl = document.getElementById('lst-interval');
                if (editing.sourceUrl && intervalEl) {
                    const n = parseInt(intervalEl.value, 10);
                    if (!isNaN(n) && n >= 1) body.interval_hours = n;
                }
                r = await API.put('/api/lists/' + encodeURIComponent(editing.id),
                                  body);
            }
            if (r && r.ok) { Toast.success('Сохранено'); editing = null; await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    async function del(id) {
        if (!confirm('Удалить список?')) return;
        try {
            const r = await API.delete('/api/lists/' + encodeURIComponent(id));
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ─── список → маршрут (единый слой) ───

    function methodOptions() {
        const opts = [['nfqws2', 'nfqws2 (обход DPI)'], ['direct', 'Прямой (direct)']];
        interfaces.forEach(i => {
            const kind = (i.source === 'singbox') ? 'singbox'
                       : (i.source === 'mihomo') ? 'mihomo' : 'awg';
            opts.push([kind + ':' + i.name,
                       `${kind} → ${i.name}${i.active ? ' (активен)' : ''}`]);
        });
        // По умолчанию первый туннель, если есть; иначе nfqws2.
        const def = interfaces.length
            ? (() => { const i = interfaces[0];
                const k = (i.source === 'singbox') ? 'singbox'
                        : (i.source === 'mihomo') ? 'mihomo' : 'awg';
                return k + ':' + i.name; })()
            : 'nfqws2';
        return opts.map(([v, l]) =>
            `<option value="${escAttr(v)}" ${v === def ? 'selected' : ''}>${esc(l)}</option>`
        ).join('');
    }

    function openRoute(listId, listName) {
        routeFor = { listId, listName };
        renderRoutePicker();
        const box = document.getElementById('lists-route');
        if (box) box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function closeRoute() { routeFor = null; renderRoutePicker(); }

    function renderRoutePicker() {
        const box = document.getElementById('lists-route');
        if (!box) return;
        if (!routeFor) { box.innerHTML = ''; return; }
        const noTunnels = interfaces.length === 0;
        box.innerHTML = `
            <div class="card" style="margin-bottom:16px; border:1px solid var(--accent,#39c45e);">
                <div style="display:flex; justify-content:space-between;">
                    <div class="card-title">Маршрут для списка «${esc(routeFor.listName)}»</div>
                    <button class="btn btn-ghost btn-sm" data-action="close-route">Закрыть</button>
                </div>
                <p class="text-muted" style="font-size:12px; margin:6px 0;">
                    Создаст правило в «Маршрутизации»: домены/CIDR этого списка
                    пойдут через выбранный метод. Дальше его можно донастроить
                    на странице «Маршрутизация» (fallback, мониторинг).
                    ${noTunnels ? '<br><strong>Туннели не найдены</strong> — доступны direct/nfqws2; для прокси сначала поднимите sing-box/mihomo/AWG.' : ''}
                </p>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <label class="text-muted">Метод:</label>
                    <select id="lst-route-method" class="form-control" style="max-width:320px;">${methodOptions()}</select>
                    <button class="btn btn-primary btn-sm" ${busy?'disabled':''}
                            data-action="create-route">Создать маршрут</button>
                </div>
            </div>`;
    }

    async function createRoute() {
        if (!routeFor) return;
        const method = document.getElementById('lst-route-method').value;
        busy = true; renderRoutePicker();
        try {
            const payload = {
                name: 'Список: ' + routeFor.listName,
                method,
                enabled: true,
                destination: { list_ids: [routeFor.listId] },
            };
            const r = await API.post('/api/unified/routes', payload);
            if (r && r.ok) {
                Toast.success('Маршрут создан');
                routeFor = null;
                renderRoutePicker();
            } else {
                Toast.error((r && r.error) || 'не удалось создать маршрут');
            }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderRoutePicker(); }
    }

    // ─── курируемые списки ───

    function onCuratedUrl(v) { curatedUrl = v; }

    function onCuratedInterval(v) {
        const n = parseInt(v, 10);
        curatedInterval = (isNaN(n) || n < 1) ? 12 : n;
    }

    async function setTransport(v) {
        try {
            const r = await API.post('/api/lists/curated/settings',
                                     { transport: v || '' });
            if (r && r.ok) {
                curated.transport = r.transport || '';
                Toast.success('Транспорт скачивания сохранён');
            } else {
                Toast.error((r && r.error) || 'не удалось сохранить');
            }
        } catch (e) { Toast.error(e.message); }
        renderCurated();
    }

    async function addPreset(url) {
        busy = true; renderCurated();
        try {
            const r = await API.post('/api/lists/curated', { url });
            if (r && r.ok) {
                const rr = r.refresh;
                Toast.success(rr && rr.ok
                    ? `Добавлен: ${rr.domains||0} доменов`
                    : 'Список добавлен');
                await refresh();
            } else { Toast.error((r && r.error) || 'не удалось'); }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderCurated(); }
    }

    async function addPresetToRoute(url, name) {
        busy = true; renderCurated();
        try {
            // 1. Добавляем пресет как named list (если ещё нет)
            let listId = null;
            const existing = lists.find(l => l.source_url === url);
            if (existing) {
                listId = existing.id;
            } else {
                const r = await API.post('/api/lists/curated', { url });
                if (!r || !r.ok) {
                    Toast.error((r && r.error) || 'Не удалось добавить список');
                    return;
                }
                listId = r.id;
                await refresh();
            }

            if (!listId) {
                Toast.error('Не удалось определить list_id');
                return;
            }

            // 2. Создаём маршрут через unified routing
            const payload = {
                name: 'Список: ' + (name || url.split('/').pop()),
                method: 'nfqws2',
                enabled: true,
                destination: { list_ids: [listId] },
            };
            const r2 = await API.post('/api/unified/routes', payload);
            if (r2 && r2.ok) {
                Toast.success('Маршрут создан для ' + (name || 'списка'));
            } else {
                Toast.warning('Список добавлен, но маршрут не создан: ' +
                    ((r2 && r2.error) || 'ошибка'));
            }
            await refresh();
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderCurated(); }
    }

    async function addCustomUrl() {
        const url = (curatedUrl || '').trim();
        if (!url) { Toast.error('Укажите URL'); return; }
        busy = true; renderCurated();
        try {
            const r = await API.post('/api/lists/curated',
                                     { url, interval_hours: curatedInterval });
            if (r && r.ok) { Toast.success('Список добавлен'); curatedUrl = ''; await refresh(); }
            else { Toast.error((r && r.error) || 'не удалось'); }
        } catch (e) { Toast.error(e.message); }
        finally { busy = false; renderCurated(); }
    }

    async function refreshList(id) {
        try {
            const r = await API.post('/api/lists/' + encodeURIComponent(id) + '/refresh');
            if (r && r.ok) Toast.success(`Обновлён: ${r.domains||0} доменов, ${r.cidrs||0} CIDR`);
            else Toast.warning((r && r.error) || 'не обновлено');
            await refresh();
        } catch (e) { Toast.error(e.message); }
    }

    async function refreshAllManaged() {
        try {
            await API.post('/api/lists/refresh-all');
            Toast.success('Обновление списков запущено');
            await refresh();
        } catch (e) { Toast.error(e.message); }
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }

    return { render, destroy, refresh, newList, edit, closeEditor, save, del,
             onCuratedUrl, onCuratedInterval, setTransport,
             addPreset, addPresetToRoute, addCustomUrl, refreshList, refreshAllManaged,
             openRoute, closeRoute, createRoute };
})();
