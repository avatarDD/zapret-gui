/**
 * history.js — «История изменений»: версии файлов, разница, откат.
 *
 * Бэкенд — core/file_history.py (/api/history*) и рабочая точка из
 * core/safe_apply.py (/api/safe-apply*). Отслеживаются settings.json,
 * свои стратегии, хостлисты и ipset'ы — в том числе правки вне GUI.
 */

const HistoryPage = (() => {
    let data = null;
    let safe = null;
    let fileFilter = '';

    const SOURCE_LABEL = {
        gui: 'GUI', external: 'вне GUI', restore: 'откат', auto: 'автообновление',
    };

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function when(ts) {
        const d = new Date(ts * 1000);
        const pad = n => String(n).padStart(2, '0');
        return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + ' '
            + pad(d.getHours()) + ':' + pad(d.getMinutes());
    }

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">История изменений</h1>
                    <p class="page-description">Что, когда и кем менялось в настройках, своих стратегиях и списках — с разницей и откатом. Правки вне GUI (по ssh, скриптом) тоже попадают сюда.</p>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-ghost" onclick="HistoryPage.scanNow()">Проверить правки вне GUI</button>
                </div>
            </div>
            <div class="card" id="hist-working"><div class="text-muted">Загрузка…</div></div>
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:8px;">
                    <div id="hist-undo"></div>
                    <select class="form-input" id="hist-file" style="max-width:280px;" onchange="HistoryPage.setFilter(this.value)"></select>
                </div>
                <div id="hist-list"><div class="text-muted">Загрузка…</div></div>
            </div>
            <div class="modal-backdrop" id="hist-diff-modal" style="display:none;">
                <div class="modal-content" style="max-width:900px;">
                    <div class="modal-header">
                        <h3 class="modal-title" id="hist-diff-title">Разница</h3>
                        <button class="modal-close" onclick="HistoryPage.closeDiff()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <pre id="hist-diff-body" style="max-height:60vh; overflow:auto; font-size:12px; white-space:pre-wrap; word-break:break-all;"></pre>
                    </div>
                </div>
            </div>`;
        load();
    }

    async function load() {
        try {
            const q = fileFilter ? '?file=' + encodeURIComponent(fileFilter) : '';
            [data, safe] = await Promise.all([
                API.get('/api/history' + q), API.get('/api/safe-apply')]);
        } catch (e) {
            const list = document.getElementById('hist-list');
            if (list) list.innerHTML = '<div class="text-muted">Не удалось загрузить: ' + esc(e.message) + '</div>';
            return;
        }
        renderWorking();
        renderUndo();
        renderFiles();
        renderList();
    }

    function renderWorking() {
        const box = document.getElementById('hist-working');
        if (!box) return;
        const w = safe && safe.working;
        const changed = (safe && safe.changed_since_working) || [];
        let html = '<div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; align-items:center;">';
        if (w) {
            html += '<div><b>Рабочее состояние</b> от ' + esc(when(w.ts)) + ' — '
                + esc(w.note || '') + (w.strategy_name ? ', стратегия «' + esc(w.strategy_name) + '»' : '')
                + '<div class="form-hint" style="margin:4px 0 0;">'
                + (changed.length ? 'С тех пор изменились: ' + changed.map(esc).join(', ')
                    : 'С тех пор файлы не менялись.') + '</div></div>';
        } else {
            html += '<div><b>Рабочее состояние не отмечено.</b><div class="form-hint" style="margin:4px 0 0;">'
                + 'Оно запоминается, когда вы подтверждаете стратегию после «Применить с проверкой», или вручную кнопкой справа.</div></div>';
        }
        html += '<div style="display:flex; gap:8px; flex-wrap:wrap;">'
            + '<button class="btn btn-ghost btn-sm" onclick="HistoryPage.markWorking()">Отметить текущее рабочим</button>'
            + (w ? '<button class="btn btn-primary btn-sm" onclick="HistoryPage.restoreWorking()"'
                + (changed.length ? '' : ' disabled') + '>Вернуть рабочее состояние</button>' : '')
            + '</div></div>';
        box.innerHTML = html;
    }

    function renderUndo() {
        const box = document.getElementById('hist-undo');
        if (!box) return;
        const u = data && data.undo;
        box.innerHTML = u
            ? '<button class="btn btn-ghost btn-sm" onclick="HistoryPage.undo()" title="' + esc(u.files.join(', ')) + '">'
                + 'Отменить последнее: ' + esc(u.label) + '</button>'
            : '<span class="text-muted" style="font-size:13px;">Отменять нечего</span>';
    }

    function renderFiles() {
        const sel = document.getElementById('hist-file');
        if (!sel) return;
        const files = (data && data.files) || [];
        sel.innerHTML = '<option value="">Все файлы</option>'
            + files.map(f => '<option value="' + esc(f) + '"' + (f === fileFilter ? ' selected' : '')
                + '>' + esc(f) + '</option>').join('');
    }

    function renderList() {
        const box = document.getElementById('hist-list');
        if (!box) return;
        if (data && data.enabled === false) {
            box.innerHTML = '<div class="text-muted">История выключена (history.enabled в настройках).</div>';
            return;
        }
        const groups = (data && data.groups) || [];
        if (!groups.length) {
            box.innerHTML = '<div class="text-muted">Пока ничего не менялось. Первые версии появятся после сохранения настроек, стратегии или списка.</div>';
            return;
        }
        box.innerHTML = groups.map(g => {
            const rows = g.entries.map(e => {
                const state = e.created ? ' (создан)' : e.deleted ? ' (удалён)' : '';
                // Разделы settings.json, которые поменялись (awg, strategy…).
                const parts = (e.sections || []).length ? ': ' + e.sections.join(', ') : '';
                return '<div style="display:flex; justify-content:space-between; gap:8px; align-items:center; padding:4px 0; flex-wrap:wrap;">'
                    + '<span style="font-family:var(--font-mono, monospace); font-size:12px;'
                    + (e.undone ? ' text-decoration:line-through;' : '') + '">' + esc(e.file) + esc(parts) + esc(state) + '</span>'
                    + '<span style="display:flex; gap:6px;">'
                    + '<button class="btn btn-ghost btn-sm" onclick="HistoryPage.showDiff(' + e.id + ')">Разница</button>'
                    + '<button class="btn btn-ghost btn-sm" onclick="HistoryPage.restore(' + e.id + ')" title="Вернуть файл к виду до этой правки">Вернуть как было</button>'
                    + '</span></div>';
            }).join('');
            return '<div style="border-top:1px solid var(--border); padding:8px 0;">'
                + '<div style="display:flex; gap:8px; align-items:baseline; flex-wrap:wrap;">'
                + '<b>' + esc(g.label) + '</b>'
                + '<span class="badge">' + esc(SOURCE_LABEL[g.source] || g.source) + '</span>'
                + '<span class="text-muted" style="font-size:12px;">' + esc(when(g.ts)) + '</span></div>'
                + rows + '</div>';
        }).join('');
    }

    function setFilter(v) {
        fileFilter = v || '';
        load();
    }

    async function showDiff(id) {
        const modal = document.getElementById('hist-diff-modal');
        const body = document.getElementById('hist-diff-body');
        const title = document.getElementById('hist-diff-title');
        if (!modal || !body) return;
        modal.style.display = 'flex';
        body.textContent = 'Загрузка…';
        try {
            const r = await API.get('/api/history/diff?id=' + encodeURIComponent(id));
            if (!r.ok) { body.textContent = r.error || 'Нет данных'; return; }
            if (title) title.textContent = 'Разница: ' + r.entry.file + ' · ' + when(r.entry.ts);
            body.textContent = (r.diff || '(без изменений по тексту)')
                + (r.truncated ? '\n… разница обрезана' : '');
        } catch (e) {
            body.textContent = 'Ошибка: ' + e.message;
        }
    }

    function closeDiff() {
        const modal = document.getElementById('hist-diff-modal');
        if (modal) modal.style.display = 'none';
    }

    function report(r, okText) {
        if (r.ok) {
            Toast.success(okText + (r.restored && r.restored.length ? ': ' + r.restored.join(', ') : ''));
            (r.notes || []).forEach(n => Toast.warning(n));
        } else {
            Toast.error(r.error || 'Не удалось');
        }
        if (r.skipped && r.skipped.length) {
            Toast.warning('Не тронуты (с тех пор менялись): ' + r.skipped.join(', '));
        }
        load();
    }

    async function restore(id) {
        if (!confirm('Вернуть файл к виду до этой правки? Текущая версия останется в истории.')) return;
        try { report(await API.post('/api/history/restore', { id, side: 'before' }), 'Возвращено'); }
        catch (e) { Toast.error(e.message); }
    }

    async function undo() {
        const u = data && data.undo;
        if (!u || !confirm('Отменить «' + u.label + '»?\n\nФайлы: ' + u.files.join(', '))) return;
        try { report(await API.post('/api/history/undo', {}), 'Отменено'); }
        catch (e) { Toast.error(e.message); }
    }

    async function markWorking() {
        try {
            const r = await API.post('/api/safe-apply/mark-working', {});
            if (r.ok) Toast.success('Текущее состояние отмечено рабочим');
            load();
        } catch (e) { Toast.error(e.message); }
    }

    async function restoreWorking() {
        const changed = (safe && safe.changed_since_working) || [];
        if (!confirm('Вернуть рабочее состояние?\n\nБудут возвращены: ' + changed.join(', ')
            + '\nДвижок перезапустится с прежними аргументами.')) return;
        try { report(await API.post('/api/safe-apply/restore-working', {}), 'Рабочее состояние возвращено'); }
        catch (e) { Toast.error(e.message); }
    }

    async function scanNow() {
        try {
            const r = await API.post('/api/history/scan', {});
            Toast.info(r.changed ? 'Найдены правки вне GUI: ' + (r.files || []).join(', ')
                : 'Правок вне GUI нет');
            load();
        } catch (e) { Toast.error(e.message); }
    }

    return { render, setFilter, showDiff, closeDiff, restore, undo,
             markWorking, restoreWorking, scanNow };
})();
