/**
 * device_quota.js — карточка «Квоты времени» (core/device_quota.py).
 *
 * N минут интернета в день на устройство, потом доступ закрыт до
 * полуночи. Сервер: GET/POST /api/device-quota, «добавить минут» —
 * POST /api/device-quota/grant. Монтируется в страницу «Управление».
 */

const DeviceQuota = (() => {
    const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];

    let host = null;
    let st = { enabled: false, tz_offset: '', active_packets: 30, rules: [] };
    let status = {};
    let devices = [];
    let dirty = false;

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function fromServer(settings) {
        const out = Object.assign({ enabled: false, tz_offset: '', active_packets: 30, rules: [] }, settings);
        out.rules = (out.rules || []).map(r => Object.assign({}, r, {
            devices: (r.devices || []).join(', '),
            days: (r.days && r.days.length) ? r.days.map(Number) : [1, 2, 3, 4, 5, 6, 7] }));
        return out;
    }

    async function load() {
        const r = await API.get('/api/device-quota');
        st = fromServer(r.settings);
        status = r.status || {};
    }

    async function mount(el) {
        host = el;
        dirty = false;
        host.innerHTML = '<div class="text-muted" style="font-size:12px;">Загрузка…</div>';
        try {
            await load();
        } catch (e) {
            host.innerHTML = `<div class="text-muted">Ошибка: ${esc(e.message)}</div>`;
            return;
        }
        draw();
        try {
            const r = await API.get('/api/devices');
            devices = (r && r.devices) || [];
            if (!dirty) draw();
        } catch (_) { /* список устройств — только подсказка */ }
    }

    function rowStatus(i) {
        const r = st.rules[i];
        const key = String(r.devices || '').toLowerCase().split(/[\s,;]+/).filter(Boolean);
        const s = (status.rules || []).find(x => x.devices.length === key.length
            && x.devices.every(d => key.includes(d)));
        if (!s || dirty) return '';
        if (!s.today) return '<span class="text-muted">сегодня без квоты</span>';
        const extra = s.extra ? ` (+${s.extra} добавлено)` : '';
        return `<span style="${s.blocked ? 'color:#e58;' : ''}">`
            + `${s.blocked ? 'Время вышло, интернет закрыт до полуночи' : 'Осталось ' + s.left + ' мин'}`
            + `</span> <span class="text-muted">· истрачено ${s.used} из ${s.minutes}${extra}</span>
            <span style="display:inline-flex; gap:4px; margin-left:6px;">
                <button class="btn btn-ghost btn-sm" data-q-grant="${esc(s.key)}" data-min="15">+15 мин</button>
                <button class="btn btn-ghost btn-sm" data-q-grant="${esc(s.key)}" data-min="60">+1 ч</button>
            </span>`;
    }

    function ruleHtml(r, i) {
        return `
        <div class="card" style="padding:8px; margin:6px 0;" data-q-rule="${i}">
            <div style="display:grid; grid-template-columns: 1fr 2fr 110px auto; gap:6px; align-items:center;">
                <input class="form-input" placeholder="Название" value="${esc(r.name)}" data-q-field="name">
                <input class="form-input" placeholder="IP или MAC через запятую" list="dq-devices"
                       value="${esc(r.devices)}" data-q-field="devices">
                <input class="form-input" type="number" min="1" max="1440" value="${esc(r.minutes)}"
                       data-q-field="minutes" title="Минут в день">
                <button class="btn btn-ghost btn-sm" data-q-del="${i}" title="Удалить правило">✕</button>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px; font-size:12px; align-items:center;">
                ${DAYS.map((d, k) => `<label style="display:flex; gap:3px; align-items:center;">
                    <input type="checkbox" data-q-day="${k + 1}" ${r.days.includes(k + 1) ? 'checked' : ''}>${d}</label>`).join('')}
                <label style="display:flex; gap:3px; align-items:center; margin-left:8px;">
                    <input type="checkbox" data-q-field="enabled" ${r.enabled !== false ? 'checked' : ''}>включено</label>
            </div>
            <div style="font-size:12px; margin-top:4px;">${rowStatus(i)}</div>
            ${r.error ? `<div style="color:#e58; font-size:12px;">${esc(r.error)}</div>` : ''}
        </div>`;
    }

    function draw() {
        if (!host) return;
        const errs = (st.errors || []).map(e => `<div style="color:#e58; font-size:12px;">${esc(e)}</div>`).join('');
        host.innerHTML = `
            <p class="form-hint" style="margin-top:0;">
                Сколько минут интернета в день у устройства. Минута засчитывается, когда
                устройство действительно пользуется сетью (не меньше
                <input class="form-input" type="number" min="1" style="width:70px; display:inline-block; padding:1px 4px;"
                       value="${esc(st.active_packets)}" data-q-top="active_packets"> пакетов за минуту),
                лежащий телефон время не тратит. Кончились минуты — доступ закрыт до полуночи
                по времени роутера${status.date ? ' (сегодня ' + esc(status.date) + ')' : ''}.
                При аппаратном ускорении NAT счёт неточен.
            </p>
            <label style="display:flex; gap:6px; align-items:center;">
                <input type="checkbox" data-q-top="enabled" ${st.enabled ? 'checked' : ''}> Квоты включены
            </label>
            ${errs}
            ${status.error ? `<div style="color:#e58; font-size:12px;">Ошибка: ${esc(status.error)}</div>` : ''}
            <datalist id="dq-devices">${devices.map(d => `<option value="${esc(d.mac || d.ip)}">${esc(d.hostname || d.ip || '')}</option>`).join('')}</datalist>
            <div>${st.rules.map(ruleHtml).join('') || '<div class="text-muted" style="font-size:12px; margin:6px 0;">Правил нет.</div>'}</div>
            <div style="display:flex; gap:6px; margin-top:6px;">
                <button class="btn btn-ghost btn-sm" data-q-add>+ Правило</button>
                <button class="btn btn-primary btn-sm" data-q-save>Сохранить</button>
            </div>`;
        bind();
    }

    function bind() {
        host.querySelectorAll('[data-q-top]').forEach(el => el.addEventListener('change', () => {
            const k = el.dataset.qTop;
            st[k] = el.type === 'checkbox' ? el.checked : Number(el.value);
            dirty = true;
        }));
        host.querySelectorAll('[data-q-rule]').forEach(box => {
            const r = st.rules[Number(box.dataset.qRule)];
            box.querySelectorAll('[data-q-field]').forEach(el => el.addEventListener('input', () => {
                const k = el.dataset.qField;
                r[k] = el.type === 'checkbox' ? el.checked : (k === 'minutes' ? Number(el.value) : el.value);
                dirty = true;
            }));
            box.querySelectorAll('[data-q-day]').forEach(el => el.addEventListener('change', () => {
                const d = Number(el.dataset.qDay);
                r.days = el.checked ? [...new Set([...r.days, d])].sort() : r.days.filter(x => x !== d);
                dirty = true;
            }));
        });
        host.querySelector('[data-q-add]')?.addEventListener('click', () => {
            st.rules.push({ name: '', devices: '', minutes: 120, days: [1, 2, 3, 4, 5, 6, 7], enabled: true });
            dirty = true;
            draw();
        });
        host.querySelectorAll('[data-q-del]').forEach(el => el.addEventListener('click', () => {
            st.rules.splice(Number(el.dataset.qDel), 1);
            dirty = true;
            draw();
        }));
        host.querySelector('[data-q-save]')?.addEventListener('click', save);
        host.querySelectorAll('[data-q-grant]').forEach(el => el.addEventListener('click', () =>
            grant(el.dataset.qGrant, Number(el.dataset.min), el)));
    }

    async function save() {
        // Пустой список дней на сервере — «каждый день»: снятые все галки
        // молча включили бы квоту на всю неделю.
        if (st.rules.some(r => !r.days.length)) {
            Toast.error('Отметьте хотя бы один день недели');
            return;
        }
        const body = {
            enabled: !!st.enabled, tz_offset: st.tz_offset || '', active_packets: st.active_packets,
            rules: st.rules.map(r => ({
                name: r.name, enabled: r.enabled !== false, minutes: r.minutes, names: r.names || {},
                devices: String(r.devices || '').split(/[\s,;]+/).filter(Boolean),
                // Все семь дней — «каждый день» (пустой список на сервере).
                days: r.days.length === 7 ? [] : r.days })),
        };
        try {
            const r = await API.post('/api/device-quota', body);
            if (!r.ok) { Toast.error(r.error || 'Не сохранено'); return; }
            st = fromServer(r.settings);
            status = r.status || {};
            dirty = false;
            Toast.success('Квоты сохранены');
            draw();
        } catch (e) {
            Toast.error(e.message);
        }
    }

    async function grant(key, minutes, btn) {
        if (btn) btn.disabled = true;
        try {
            const r = await API.post('/api/device-quota/grant', { rule: key, minutes });
            if (!r.ok) { Toast.error(r.error || 'Не вышло'); return; }
            Toast.success('Осталось ' + r.left + ' мин');
            status = r.status || status;
            draw();
        } catch (e) {
            Toast.error(e.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    return { mount };
})();
