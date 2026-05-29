/**
 * lists.js — страница «Списки».
 *
 * Именованные списки доменов/CIDR (core/named_lists), общие для
 * nfqws2-hostlist'ов и единого слоя маршрутизации. CRUD + импорт текстом.
 */

const ListsPage = (() => {

    let lists = [];
    let editing = null;   // {id?, name, description, text, isNew}

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Списки</h1>
                    <p class="page-description">
                        Именованные списки доменов и IP/CIDR. Используются
                        в «Маршрутизации» (назначение → метод) и как
                        hostlist'ы nfqws2.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="ListsPage.newList()">+ Список</button>
                    <button class="btn btn-ghost btn-sm" onclick="ListsPage.refresh()">Обновить</button>
                </div>
            </div>
            <div id="lists-editor"></div>
            <div id="lists-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
        `;
        refresh();
    }
    function destroy() {}

    async function refresh() {
        try {
            const r = await API.get('/api/lists');
            lists = (r && r.lists) || [];
        } catch (e) { Toast.error(e.message); lists = []; }
        renderEditor();
        renderBody();
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
                <th>Описание</th><th style="width:120px;"></th></tr></thead>
            <tbody>${lists.map(l => `
                <tr>
                    <td><strong>${esc(l.name)}</strong></td>
                    <td>${l.domain_count}</td>
                    <td>${l.cidr_count}</td>
                    <td>${esc(l.description || '')}</td>
                    <td style="text-align:right;">
                        <button class="btn btn-ghost btn-sm" onclick="ListsPage.edit('${esc(l.id)}')">Ред.</button>
                        <button class="btn btn-ghost btn-sm" onclick="ListsPage.del('${esc(l.id)}')">✕</button>
                    </td>
                </tr>`).join('')}
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
                    <button class="btn btn-ghost btn-sm" onclick="ListsPage.closeEditor()">Закрыть</button>
                </div>
                <div style="display:grid; grid-template-columns:120px 1fr; gap:8px 12px; margin-top:8px;">
                    <label class="text-muted" style="padding-top:6px;">Имя</label>
                    <input id="lst-name" class="form-control" style="max-width:320px;"
                           value="${escAttr(editing.name)}">
                    <label class="text-muted" style="padding-top:6px;">Описание</label>
                    <input id="lst-desc" class="form-control" style="max-width:480px;"
                           value="${escAttr(editing.description)}">
                    <label class="text-muted" style="padding-top:6px;">Записи</label>
                    <textarea id="lst-text" spellcheck="false"
                              placeholder="Домены и/или CIDR, по одному в строке или через запятую"
                              style="width:100%; min-height:220px; font-family:monospace; font-size:12px;">${esc(editing.text)}</textarea>
                </div>
                <div style="margin-top:10px;">
                    <button class="btn btn-primary btn-sm" onclick="ListsPage.save()">Сохранить</button>
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
                        text, isNew: false };
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
                r = await API.put('/api/lists/' + encodeURIComponent(editing.id),
                                  { name, description, entries, replace: true });
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

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    function escAttr(s) { return esc(s).replace(/"/g,'&quot;'); }

    return { render, destroy, refresh, newList, edit, closeEditor, save, del };
})();
