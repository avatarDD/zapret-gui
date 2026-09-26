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
    let routes = [];          // маршруты единого слоя — «где используется»
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
            <div class="page-header page-header-bar">
                <div>
                    <h1 class="page-title">Списки маршрутизации${typeof Help !== 'undefined' ? Help.button('lists') : ''}</h1>
                    <p class="page-description">
                        Наборы доменов и IP-подсетей под именем. Список сам по
                        себе ничего не меняет — его подключают к маршруту:
                        «эти сайты → через туннель» или «→ обход DPI».
                    </p>
                </div>
                <div class="page-actions">
                    <button class="btn btn-ghost btn-sm" data-action="refresh-all-managed"
                            title="Скачать заново все списки, у которых есть источник (URL)">↻ Обновить из источников</button>
                    <button class="btn btn-primary btn-sm" data-action="new-list">+ Создать список</button>
                </div>
            </div>
            <div id="lists-route"></div>
            <div id="lists-editor"></div>
            <div id="lists-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
            <div id="lists-curated"></div>
        `;
        _bindEvents(container);
        refresh();
    }
    function destroy() {}

    async function refresh() {
        try {
            const [r, c, ifc, tr, rt] = await Promise.all([
                API.get('/api/lists'),
                API.get('/api/lists/curated').catch(() => null),
                API.get('/api/routing/interfaces').catch(() => null),
                TransportSelect.load().catch(() => null),
                API.get('/api/unified/routes').catch(() => null),
            ]);
            lists = (r && r.lists) || [];
            routes = (rt && rt.routes) || [];
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
            countries: 'Всё заблокированное в стране',
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
            const chips = items.map(p => p.added
                ? `<span class="btn-chip btn-chip-done" title="${escAttr(p.description||p.url)}">✓ ${esc(p.name)}</span>`
                : `<button class="btn-chip" ${busy?'disabled':''}
                        title="${escAttr(p.description||p.url)}"
                        data-action="add-preset" data-url="${escAttr(p.url)}">+ ${esc(p.name)}</button>`
            ).join(' ');
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
            <div class="card">
                <div class="card-title">Готовые списки</div>
                <p class="text-muted" style="font-size:12px; margin:4px 0 10px;">
                    Списки доменов популярных сервисов от сообщества
                    (itdoginfo/allow-domains). Добавляются одним нажатием и
                    обновляются сами; ваши правки при обновлении сохраняются.
                </p>
                ${groupsHtml}
                <details class="lists-more" style="margin-top:12px;">
                    <summary>Свой список по ссылке и настройки скачивания</summary>
                    <div style="display:flex; gap:6px; margin-top:10px; flex-wrap:wrap; align-items:center;">
                        <input id="lst-curated-url" class="form-control" style="flex:1; min-width:220px;"
                               placeholder="https://… — текстовый файл, по домену в строке"
                               value="${escAttr(curatedUrl)}"
                               data-action="curated-url-input">
                        <label class="text-muted" style="font-size:12px;">обновлять каждые</label>
                        <input id="lst-curated-interval" type="number" min="1" step="1"
                               class="form-control" style="width:70px;"
                               title="Интервал автообновления, часов"
                               value="${curatedInterval}"
                               data-action="curated-interval-change">
                        <span class="text-muted" style="font-size:12px;">ч</span>
                        <button class="btn btn-primary btn-sm" ${busy?'disabled':''}
                                data-action="add-custom-url">Добавить</button>
                    </div>
                    <div style="display:flex; gap:8px; margin-top:10px; align-items:center; flex-wrap:wrap;">
                        <label class="text-muted" style="font-size:12px;">Скачивать через:</label>
                        <select class="form-control" style="max-width:300px;"
                                data-action="set-transport">
                            ${TransportSelect.optionsHtml(transports, curated.transport)}
                        </select>
                        <span class="text-muted" style="font-size:11px;">
                            если GitHub недоступен напрямую — выберите туннель
                        </span>
                    </div>
                </details>
            </div>`;
    }

    /** Маршруты, которые берут этот список. */
    function routesUsing(listId) {
        return routes.filter(r => ((r.destination || {}).list_ids || []).includes(listId));
    }

    function plural(n, one, few, many) {
        const m10 = n % 10, m100 = n % 100;
        if (m10 === 1 && m100 !== 11) return one;
        if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
        return many;
    }

    function ago(ts) {
        if (!ts) return 'ещё не обновлялся';
        const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (s < 90) return 'обновлён только что';
        if (s < 3600) return `обновлён ${Math.round(s / 60)} мин назад`;
        if (s < 86400) return `обновлён ${Math.round(s / 3600)} ч назад`;
        return 'обновлён ' + new Date(ts * 1000).toLocaleDateString('ru-RU');
    }

    function renderBody() {
        const box = document.getElementById('lists-body');
        if (!box) return;
        if (!lists.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Списков пока нет. Добавьте готовый ниже или нажмите
                «+ Создать список».</div></div>`;
            return;
        }
        box.innerHTML = `<div class="card nl-card">${lists.map(l => {
            const managed = !!(l.source_url && String(l.source_url).trim());
            const nd = l.domain_count || 0, nc = l.cidr_count || 0;
            const parts = [];
            if (nd || !nc) parts.push(`${nd} ${plural(nd, 'домен', 'домена', 'доменов')}`);
            if (nc) parts.push(`${nc} ${plural(nc, 'подсеть', 'подсети', 'подсетей')}`);
            let src = '';
            if (managed) {
                const st = l.last_status;
                const cls = st === 'ok' ? 'badge-success'
                    : (st === 'error' ? 'badge-danger'
                       : (st === 'empty' ? 'badge-warning' : 'badge-muted'));
                src = `<span class="badge ${cls}" title="${escAttr(l.source_url)}">
                        авто · раз в ${parseInt(l.interval_hours, 10) || 12} ч</span>
                    <span class="text-muted">${esc(ago(l.last_refresh))}</span>
                    ${l.last_error ? `<span class="nl-error">${esc(l.last_error)}</span>` : ''}`;
            }
            const used = routesUsing(l.id);
            const usedHtml = used.length
                ? `<div class="nl-used">→ ${used.map(r => `<a href="#routing">${esc(r.name)}</a>`).join(', ')}</div>`
                : `<div class="nl-used nl-unused">не подключён ни к одному маршруту</div>`;
            return `
            <div class="nl-row">
                <div class="nl-main">
                    <div class="nl-name">${esc(l.name)}</div>
                    <div class="nl-meta">
                        <span>${parts.join(' · ')}</span>
                        ${src}
                    </div>
                    ${l.description ? `<div class="nl-desc">${esc(l.description)}</div>` : ''}
                    ${usedHtml}
                </div>
                <div class="nl-actions">
                    ${used.length ? '' : `<button class="btn btn-primary btn-sm" title="Создать маршрут для этого списка"
                        data-action="open-route" data-id="${esc(l.id)}" data-name="${escAttr(l.name)}">Подключить к маршруту</button>`}
                    <button class="btn btn-ghost btn-sm" data-action="edit" data-id="${esc(l.id)}">Изменить</button>
                    ${managed ? `<button class="btn btn-ghost btn-sm" title="Скачать заново из источника"
                        data-action="refresh-list" data-id="${esc(l.id)}">↻</button>` : ''}
                    <button class="btn btn-ghost btn-sm nl-del" title="Удалить список"
                        data-action="del" data-id="${esc(l.id)}">✕</button>
                </div>
            </div>`; }).join('')}
        </div>`;
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
        const used = routesUsing(id);
        const msg = used.length
            ? `Список подключён к маршрутам: ${used.map(r => r.name).join(', ')}.\n` +
              'После удаления они перестанут получать из него домены. Удалить?'
            : 'Удалить список?';
        if (!confirm(msg)) return;
        try {
            const r = await API.delete('/api/lists/' + encodeURIComponent(id));
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ─── список → маршрут (единый слой) ───

    /** Метод-kind по источнику интерфейса (usque → warp:<iface>). */
    function kindForSource(source) {
        if (source === 'singbox') return 'singbox';
        if (source === 'mihomo') return 'mihomo';
        if (source === 'usque') return 'warp';
        return 'awg';
    }

    function methodOptions() {
        const KIND = { awg: 'AmneziaWG', singbox: 'sing-box', mihomo: 'mihomo', warp: 'WARP (MASQUE)' };
        const opts = [];
        interfaces.forEach(i => {
            const kind = kindForSource(i.source);
            opts.push([kind + ':' + i.name,
                       `Туннель ${KIND[kind] || kind} · ${i.name}${i.active ? '' : ' (сейчас не поднят)'}`]);
        });
        opts.push(['nfqws2', 'Обход DPI (nfqws2) — без туннеля']);
        opts.push(['direct', 'Напрямую (исключение)']);
        // По умолчанию первый туннель, если есть; иначе nfqws2.
        const def = interfaces.length
            ? kindForSource(interfaces[0].source) + ':' + interfaces[0].name
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
                await refresh();
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
        // Раньше «→» молча создавал маршрут с методом nfqws2 — даже когда
        // список заводили ради туннеля. Теперь открываем выбор метода.
        const existing = lists.find(l => l.source_url === url);
        if (existing) { openRoute(existing.id, existing.name); return; }
        await addPreset(url);
        const added = lists.find(l => l.source_url === url);
        if (added) openRoute(added.id, added.name || name);
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
