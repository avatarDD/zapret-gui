/**
 * routing_unified.js — единая страница «Маршрутизация» (назначение → метод).
 *
 * Таблица: назначение | метод (active) | статус | успешность | действия.
 * Форма: селекторы назначения (домены/CIDR/списки/geosite/geoip),
 * метод + fallback-цепочка, флаги мониторинга/failover.
 * Тумблер фонового мониторинга, кнопка «Применить все», per-route
 * подбор стратегии (для nfqws2) и применение лучшей найденной.
 *
 * Бэкенд: /api/unified/*, /api/lists, /api/routing/interfaces.
 */

const RoutingUnifiedPage = (() => {

    let routes = [];
    let statusMap = {};       // id → status entry из /api/unified/status
    let interfaces = [];
    let namedLists = [];
    let monitorRunning = false;
    let editing = null;
    let pollTimer = null;

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Маршрутизация</h1>
                    <p class="page-description">
                        Единый слой: для каждого назначения — через что пустить
                        трафик (direct / nfqws2 / туннель), с резервными методами
                        и авто-переключением по доступности.
                    </p>
                </div>
                <div style="display:flex; gap:8px; align-items:center;">
                    <label class="text-muted" style="font-size:12px; display:flex; gap:6px; align-items:center;">
                        <input type="checkbox" id="ru-monitor" onchange="RoutingUnifiedPage.toggleMonitor(this.checked)">
                        Мониторинг
                    </label>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.newRoute()">+ Маршрут</button>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.applyAll()">Применить все</button>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.refresh()">Обновить</button>
                </div>
            </div>
            <div id="ru-editor"></div>
            <div id="ru-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
            <div class="text-muted" style="margin-top:14px; font-size:12px;">
                Классические инструменты (расширенный режим):
                <a href="#strategies" style="text-decoration:underline;">Стратегии</a> ·
                <a href="#awg-routing" style="text-decoration:underline;">Routing (AWG)</a> ·
                <a href="#scan" style="text-decoration:underline;">Подбор стратегий</a> ·
                <a href="#lists" style="text-decoration:underline;">Списки</a>
            </div>
        `;
        loadAux().then(refresh);
        pollTimer = setInterval(refreshStatus, 7000);
    }
    function destroy() { if (pollTimer) clearInterval(pollTimer); pollTimer = null; }

    async function loadAux() {
        try {
            const [ifResp, listResp] = await Promise.all([
                API.get('/api/routing/interfaces').catch(() => null),
                API.get('/api/lists').catch(() => null),
            ]);
            interfaces = (ifResp && ifResp.interfaces) || [];
            namedLists = (listResp && listResp.lists) || [];
        } catch (_) {}
    }

    async function refresh() {
        try {
            const r = await API.get('/api/unified/routes');
            routes = (r && r.routes) || [];
        } catch (e) { Toast.error(e.message); }
        await refreshStatus();
        renderEditor();
        renderBody();
    }

    async function refreshStatus() {
        try {
            const s = await API.get('/api/unified/status');
            statusMap = {};
            (s.routes || []).forEach(x => statusMap[x.id] = x);
            monitorRunning = !!s.monitor_running;
            const cb = document.getElementById('ru-monitor');
            if (cb) cb.checked = monitorRunning;
            renderBody();
        } catch (_) {}
    }

    // ─────── method options ───────

    function methodOptions(selected) {
        const opts = [['direct', 'Прямой (direct)'], ['nfqws2', 'nfqws2 (обход DPI)']];
        interfaces.forEach(i => {
            const kind = (i.source === 'singbox') ? 'singbox'
                       : (i.source === 'mihomo') ? 'mihomo' : 'awg';
            const tok = kind + ':' + i.name;
            opts.push([tok, `${kind} → ${i.name}${i.active ? ' (активен)' : ''}`]);
        });
        return opts.map(([v, l]) =>
            `<option value="${escAttr(v)}" ${v === selected ? 'selected' : ''}>${esc(l)}</option>`
        ).join('');
    }

    // ─────── table ───────

    function renderBody() {
        const box = document.getElementById('ru-body');
        if (!box) return;
        if (!routes.length) {
            box.innerHTML = `<div class="card"><div class="text-muted">
                Маршрутов нет. Нажмите «+ Маршрут».</div></div>`;
            return;
        }
        box.innerHTML = `<div class="card"><table class="table">
            <thead><tr>
                <th>Маршрут</th><th>Назначение</th><th>Метод</th>
                <th>Статус</th><th>Успешность</th><th style="width:230px;"></th>
            </tr></thead>
            <tbody>${routes.map(rowHtml).join('')}</tbody>
        </table></div>`;
    }

    function rowHtml(r) {
        const st = statusMap[r.id] || {};
        const dest = r.destination || {};
        const destSummary = [
            (dest.domains || []).length ? `${dest.domains.length} дом.` : '',
            (dest.cidrs || []).length ? `${dest.cidrs.length} CIDR` : '',
            (dest.list_ids || []).length ? `${dest.list_ids.length} спис.` : '',
            (dest.geosite || []).length ? `geosite:${dest.geosite.join(',')}` : '',
            (dest.geoip || []).length ? `geoip:${dest.geoip.join(',')}` : '',
        ].filter(Boolean).join(', ') || '—';
        const active = st.active_method || r.method;
        const mon = st.monitor || {};
        const rate = (mon.rate == null) ? '—' : Math.round(mon.rate * 100) + '%';
        const rateColor = (mon.rate == null) ? 'var(--text-muted,#888)'
                        : (mon.rate >= 0.5 ? '#39c45e' : '#e58');
        const enabledDot = r.enabled
            ? '<span style="color:#39c45e;">●</span>'
            : '<span class="text-muted">○</span>';
        const scanBtn = st.suggest_scan
            ? `<button class="btn btn-ghost btn-sm" title="${escAttr(st.suggest_reason||'')}"
                       onclick="RoutingUnifiedPage.scan('${esc(r.id)}')">Подобрать</button>`
            : '';
        return `<tr>
            <td>${enabledDot} <strong>${esc(r.name)}</strong>
                ${r.failover_enabled ? '<span class="text-muted" style="font-size:10px;"> failover</span>' : ''}</td>
            <td style="font-size:12px;">${esc(destSummary)}</td>
            <td style="font-family:monospace; font-size:12px;">
                ${esc(active)}${active !== r.method ? ` <span class="text-muted">(осн. ${esc(r.method)})</span>` : ''}
                ${(r.fallbacks||[]).length ? `<br><span class="text-muted" style="font-size:10px;">↳ ${esc((r.fallbacks||[]).join(', '))}</span>` : ''}</td>
            <td>${r.monitor_enabled ? (mon.last_ok == null ? 'ждём' : (mon.last_ok ? 'ok' : 'сбой')) : '—'}</td>
            <td style="color:${rateColor};">${rate}</td>
            <td style="text-align:right;">
                ${scanBtn}
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.apply('${esc(r.id)}')">Применить</button>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.edit('${esc(r.id)}')">Ред.</button>
                <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.del('${esc(r.id)}')">✕</button>
            </td>
        </tr>`;
    }

    // ─────── editor ───────

    function blankRoute() {
        return { id: '', name: '', enabled: true, method: 'direct',
                 fallbacks: [], monitor_enabled: false, failover_enabled: false,
                 probe_domain: '',
                 destination: { domains: [], cidrs: [], list_ids: [],
                                geosite: [], geoip: [] } };
    }

    function renderEditor() {
        const box = document.getElementById('ru-editor');
        if (!box) return;
        if (!editing) { box.innerHTML = ''; return; }
        const e = editing;
        const d = e.destination || {};
        const listChecks = namedLists.map(l =>
            `<label class="text-muted" style="display:inline-flex; gap:4px; margin-right:12px; font-size:12px;">
                <input type="checkbox" value="${escAttr(l.id)}"
                       ${(d.list_ids||[]).includes(l.id) ? 'checked' : ''}
                       class="ru-listchk"> ${esc(l.name)}
            </label>`).join('') || '<span class="text-muted" style="font-size:12px;">нет списков</span>';

        box.innerHTML = `
            <div class="card" style="margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between;">
                    <div class="card-title">${e.id ? 'Редактирование маршрута' : 'Новый маршрут'}</div>
                    <button class="btn btn-ghost btn-sm" onclick="RoutingUnifiedPage.closeEditor()">Закрыть</button>
                </div>
                <div style="display:grid; grid-template-columns:150px 1fr; gap:8px 12px; margin-top:8px; align-items:start;">
                    <label class="text-muted" style="padding-top:6px;">Имя</label>
                    <input id="ru-name" class="form-control" style="max-width:320px;" value="${escAttr(e.name)}">

                    <label class="text-muted" style="padding-top:6px;">Домены</label>
                    <textarea id="ru-domains" rows="3" style="width:100%; font-family:monospace; font-size:12px;"
                        placeholder="youtube.com, googlevideo.com">${esc((d.domains||[]).join('\n'))}</textarea>

                    <label class="text-muted" style="padding-top:6px;">CIDR</label>
                    <textarea id="ru-cidrs" rows="2" style="width:100%; font-family:monospace; font-size:12px;"
                        placeholder="1.2.3.0/24">${esc((d.cidrs||[]).join('\n'))}</textarea>

                    <label class="text-muted" style="padding-top:6px;">Списки</label>
                    <div>${listChecks}</div>

                    <label class="text-muted" style="padding-top:6px;">geosite / geoip</label>
                    <div style="display:flex; gap:8px;">
                        <input id="ru-geosite" class="form-control" placeholder="geosite (google,youtube)"
                               value="${escAttr((d.geosite||[]).join(','))}" style="max-width:240px;">
                        <input id="ru-geoip" class="form-control" placeholder="geoip (ru)"
                               value="${escAttr((d.geoip||[]).join(','))}" style="max-width:160px;">
                    </div>

                    <label class="text-muted" style="padding-top:6px;">Метод</label>
                    <select id="ru-method" class="form-control" style="max-width:320px;">${methodOptions(e.method)}</select>

                    <label class="text-muted" style="padding-top:6px;">Fallback-методы</label>
                    <input id="ru-fallbacks" class="form-control" style="max-width:480px;"
                           placeholder="через запятую: awg:awg0, nfqws2, direct"
                           value="${escAttr((e.fallbacks||[]).join(', '))}">

                    <label class="text-muted" style="padding-top:6px;">Probe-домен</label>
                    <input id="ru-probe" class="form-control" style="max-width:320px;"
                           placeholder="для мониторинга (по умолч. первый домен)"
                           value="${escAttr(e.probe_domain||'')}">

                    <label class="text-muted" style="padding-top:6px;">Опции</label>
                    <div style="display:flex; gap:16px; flex-wrap:wrap; padding-top:4px;">
                        <label class="text-muted" style="font-size:12px;"><input type="checkbox" id="ru-enabled" ${e.enabled ? 'checked' : ''}> включён</label>
                        <label class="text-muted" style="font-size:12px;"><input type="checkbox" id="ru-mon" ${e.monitor_enabled ? 'checked' : ''}> мониторинг</label>
                        <label class="text-muted" style="font-size:12px;"><input type="checkbox" id="ru-fo" ${e.failover_enabled ? 'checked' : ''}> авто-переключение (failover)</label>
                    </div>
                </div>
                <div style="margin-top:12px;">
                    <button class="btn btn-primary btn-sm" onclick="RoutingUnifiedPage.save()">Сохранить</button>
                </div>
            </div>`;
    }

    function newRoute() { editing = blankRoute(); renderEditor(); }

    async function edit(id) {
        try {
            const r = await API.get('/api/unified/routes/' + encodeURIComponent(id));
            if (!r || !r.ok) { Toast.error('не найден'); return; }
            editing = r.route;
            renderEditor();
        } catch (e) { Toast.error(e.message); }
    }
    function closeEditor() { editing = null; renderEditor(); }

    function splitList(v) {
        return String(v || '').split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
    }

    async function save() {
        const listIds = Array.from(document.querySelectorAll('.ru-listchk'))
            .filter(c => c.checked).map(c => c.value);
        const payload = {
            id: editing.id || undefined,
            name: (document.getElementById('ru-name').value || '').trim(),
            enabled: document.getElementById('ru-enabled').checked,
            method: document.getElementById('ru-method').value,
            fallbacks: splitList(document.getElementById('ru-fallbacks').value),
            probe_domain: (document.getElementById('ru-probe').value || '').trim(),
            monitor_enabled: document.getElementById('ru-mon').checked,
            failover_enabled: document.getElementById('ru-fo').checked,
            destination: {
                domains: splitList(document.getElementById('ru-domains').value),
                cidrs: splitList(document.getElementById('ru-cidrs').value),
                list_ids: listIds,
                geosite: splitList(document.getElementById('ru-geosite').value),
                geoip: splitList(document.getElementById('ru-geoip').value),
            },
        };
        if (!payload.name) { Toast.error('Укажите имя'); return; }
        try {
            const r = await API.post('/api/unified/routes', payload);
            if (r && r.ok) {
                Toast.success('Сохранено');
                if (r.applied && r.applied.skipped_selectors && r.applied.skipped_selectors.length) {
                    Toast.info('Пропущено: ' + r.applied.skipped_selectors.join('; '));
                }
                editing = null; await refresh();
            } else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    async function del(id) {
        if (!confirm('Удалить маршрут?')) return;
        try {
            const r = await API.delete('/api/unified/routes/' + encodeURIComponent(id));
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    async function apply(id) {
        try {
            const r = await API.post('/api/unified/routes/' + encodeURIComponent(id) + '/apply');
            if (r && r.ok) Toast.success('Применено');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function applyAll() {
        try {
            const r = await API.post('/api/unified/apply-all');
            Toast.success('Применены все маршруты');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function toggleMonitor(enabled) {
        try {
            const r = await API.post('/api/unified/monitor', { enabled, interval: 60 });
            Toast.success('Мониторинг: ' + (r && r.running ? 'включён' : 'выключен'));
        } catch (e) { Toast.error(e.message); }
        finally { await refreshStatus(); }
    }

    async function scan(id) {
        try {
            const r = await API.post('/api/unified/routes/' + encodeURIComponent(id) + '/scan', {});
            if (r && r.ok) Toast.success('Подбор стратегии запущен для ' + r.target + ' (см. «Подбор стратегий»)');
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }

    return {
        render, destroy, refresh,
        newRoute, edit, closeEditor, save, del, apply, applyAll,
        toggleMonitor, scan,
    };
})();
