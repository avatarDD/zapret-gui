/**
 * list_subscription.js — подписка хостлиста / ipset-файла nfqws2 на URL.
 *
 * Блок для модалок страниц «Списки доменов» и «IP-списки»: URL, интервал,
 * состояние последнего обновления, «Обновить сейчас» и «Отписаться».
 * Сервер — core/list_subscriptions (ручные правки списка сохраняются,
 * пустой ответ файл не затирает).
 *
 *   ListSubscription.render(container, 'hostlists', 'other', { onChange })
 */

const ListSubscription = (() => {

    const INTERVALS = [6, 12, 24, 72, 168];

    function esc(text) {
        const div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function base(section, name) {
        return '/api/' + section + '/' + encodeURIComponent(name) + '/subscription';
    }

    function fmtTime(ts) {
        if (!ts) return 'ещё не обновлялся';
        try { return new Date(ts * 1000).toLocaleString(); }
        catch (_e) { return String(ts); }
    }

    function statusLine(sub) {
        if (!sub) return '';
        const when = fmtTime(sub.last_refresh);
        if (sub.last_status === 'ok') {
            return '✓ ' + when + ' — записей: ' + (sub.last_count || 0);
        }
        if (sub.last_status === 'error' || sub.last_status === 'empty') {
            return '⚠ ' + when + ' — ' + (sub.last_error || sub.last_status);
        }
        return when;
    }

    async function render(container, section, name, opts) {
        if (!container) return;
        opts = opts || {};
        let sub = null;
        try {
            const r = await API.get(base(section, name));
            sub = r.subscription || null;
        } catch (_e) { sub = null; }

        const interval = sub ? sub.interval_hours : 24;
        const options = INTERVALS.map(h =>
            '<option value="' + h + '"' + (h === interval ? ' selected' : '') + '>'
            + (h < 24 ? h + ' ч' : (h / 24) + ' дн') + '</option>').join('');

        container.innerHTML = `
            <div class="form-group lsub">
                <label class="form-label">Подписка по URL (автообновление)</label>
                <div class="lists-add-row">
                    <input type="text" class="form-input lsub-url"
                           placeholder="https://example.com/list.txt"
                           value="${esc(sub ? sub.url : '')}">
                    <select class="form-select lsub-interval" title="Как часто обновлять">${options}</select>
                </div>
                <div class="form-hint">
                    Список будет обновляться сам. Ваши ручные правки сохраняются, а пустой
                    или ошибочный ответ источника список не затрёт.
                </div>
                <div class="form-hint lsub-status">${esc(statusLine(sub))}</div>
                <div class="lists-add-row" style="margin-top:8px;">
                    <button class="btn btn-primary btn-sm lsub-save">${sub ? 'Сохранить' : 'Подписаться'}</button>
                    ${sub ? '<button class="btn btn-ghost btn-sm lsub-refresh">Обновить сейчас</button>' : ''}
                    ${sub ? '<button class="btn btn-danger btn-sm lsub-delete">Отписаться</button>' : ''}
                </div>
            </div>`;

        const q = sel => container.querySelector(sel);
        const done = () => {
            render(container, section, name, opts);
            if (typeof opts.onChange === 'function') opts.onChange();
        };

        q('.lsub-save').addEventListener('click', async () => {
            const url = q('.lsub-url').value.trim();
            if (!url) { Toast.warning('Введите URL'); return; }
            try {
                Toast.info('Загрузка...');
                const r = await API.put(base(section, name), {
                    url, interval_hours: parseInt(q('.lsub-interval').value, 10) || 24,
                });
                const ref = r.refresh || {};
                if (ref.ok) Toast.success('Подписка сохранена, записей: ' + ref.count);
                else Toast.warning('Подписка сохранена, но обновление не удалось: '
                                   + (ref.error || '?'));
                done();
            } catch (err) { Toast.error(err.message); }
        });
        const refreshBtn = q('.lsub-refresh');
        if (refreshBtn) refreshBtn.addEventListener('click', async () => {
            try {
                Toast.info('Обновление...');
                const r = await API.post(base(section, name) + '/refresh');
                if (r.ok) Toast.success(r.changed ? 'Обновлено, записей: ' + r.count
                                                  : 'Без изменений');
                else Toast.warning(r.error || 'Не обновлено');
            } catch (err) { Toast.error(err.message); }
            done();
        });
        const delBtn = q('.lsub-delete');
        if (delBtn) delBtn.addEventListener('click', async () => {
            try {
                await API.delete(base(section, name));
                Toast.success('Подписка снята, содержимое списка осталось');
                done();
            } catch (err) { Toast.error(err.message); }
        });
    }

    return { render };
})();
