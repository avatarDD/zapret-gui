/**
 * foreign_services.js — Сторонние экземпляры туннелей.
 *
 * Туннели usque / sing-box / mihomo / AmneziaWG / Opera Proxy /
 * Telegram-прокси, которые запустил не GUI: Entware-скрипты (S51usque,
 * S99sing-box…), ручной запуск, чужие установщики. Страница их показывает
 * и по кнопке: отключает скрипт, останавливает процесс или «усыновляет» —
 * переносит туннель в профиль GUI. Сам GUI чужое не трогает.
 */

const ForeignServicesPage = (() => {
    const TITLES = {
        usque: 'usque (MASQUE/WARP)', singbox: 'sing-box', mihomo: 'mihomo',
        awg: 'AmneziaWG', opera: 'Opera Proxy', tgproxy: 'Telegram-прокси',
    };
    let _busy = false;
    let _root = null;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Сторонние туннели</h1>
                <span class="page-subtitle">Экземпляры движков, запущенные не из GUI</span>
            </div>
            <div class="card">
                <div class="card-body form-hint">
                    Здесь видно то, что GUI не запускал: init-скрипты Entware
                    (<code>S51usque</code>, <code>S99sing-box</code>,
                    <code>S99mihomo</code>, <code>S99amneziawg</code>…), ручной
                    запуск и чужие установщики. Такой туннель работает
                    параллельно профилям GUI, занимает имена интерфейсов и
                    сам поднимается после перезагрузки. Ничего здесь не
                    меняется само — только по вашей кнопке.
                    <b>«Передать GUI»</b> переносит конфиг в профиль GUI (с тем же
                    интерфейсом), гасит чужой экземпляр, отключает его скрипт,
                    поднимает туннель силами GUI и включает ему автозапуск GUI.
                </div>
            </div>
            <div id="fs-body"><div class="card"><div class="card-body">Загрузка...</div></div></div>
        `;
        // Слушатели — на общем контейнере приложения, поэтому снимаются в
        // destroy(): иначе клики по следующей странице ловила бы эта.
        _root = container;
        container.addEventListener('click', _onClick);
        container.addEventListener('change', _onChange);
        await _refresh();
    }

    function destroy() {
        if (_root) {
            _root.removeEventListener('click', _onClick);
            _root.removeEventListener('change', _onChange);
            _root = null;
        }
    }

    async function _refresh() {
        const el = document.getElementById('fs-body');
        if (!el) return;
        try {
            const data = await API.get('/api/foreign/status');
            el.innerHTML = _renderAll(data || {});
        } catch (e) {
            el.innerHTML = `<div class="card"><div class="card-body text-error">
                Ошибка: ${esc(String(e && e.message || e))}</div></div>`;
        }
    }

    function _renderAll(d) {
        const procs = d.processes || [];
        const scripts = d.scripts || [];
        const conflicts = d.conflicts || [];
        return _renderConflicts(conflicts)
            + _renderProcesses(procs)
            + _renderScripts(scripts)
            + _renderExclusive(!!d.exclusive);
    }

    function _renderConflicts(list) {
        if (!list.length) return '';
        const rows = list.map(c => `
            <li style="margin-bottom:6px;">
                <code>${esc(c.iface)}</code>:
                ${(c.claimants || []).map(o => `<b>${esc(o.label)}</b>`
                    + `${o.kind === 'gui' ? ' (GUI)' : ''}`).join(', ')}
                <div class="form-hint">${esc(c.hint || '')}</div>
            </li>`).join('');
        return `<div class="card">
            <div class="card-title">⚠ Конфликты имён интерфейсов</div>
            <div class="card-body"><ul style="margin:0 0 0 18px;">${rows}</ul></div>
        </div>`;
    }

    function _renderProcesses(list) {
        let body;
        if (!list.length) {
            body = `<span class="text-muted">Сторонних процессов движков нет.</span>`;
        } else {
            body = `<div class="table-wrap" style="overflow-x:auto;"><table class="table"><thead><tr>
                <th>Движок</th><th>PID</th><th>Интерфейс</th><th>Конфиг</th>
                <th>Запущен скриптом</th><th></th></tr></thead><tbody>
                ${list.map(p => `<tr>
                    <td>${esc(TITLES[p.engine] || p.engine)}</td>
                    <td>${esc(String(p.pid))}</td>
                    <td>${p.iface ? `<code>${esc(p.iface)}</code>` : '—'}</td>
                    <td>${p.config ? `<code>${esc(p.config)}</code>` : '—'}</td>
                    <td>${p.script ? `<code>${esc(p.script)}</code>` : '<span class="text-muted">не определить</span>'}</td>
                    <td><div style="display:flex; flex-wrap:wrap; gap:4px; justify-content:flex-end;">
                        ${p.adoptable
                            ? `<button class="btn btn-primary btn-sm" data-act="adopt"
                                   data-engine="${esc(p.engine)}" data-pid="${esc(String(p.pid))}">Передать GUI</button>`
                            : `<span class="form-hint" title="${esc(p.adopt_hint || '')}">передать нельзя</span>`}
                        <button class="btn btn-danger btn-sm" data-act="stop"
                                data-pid="${esc(String(p.pid))}">Остановить</button>
                    </div></td></tr>
                    <tr><td colspan="6" class="form-hint" style="padding-top:0;">
                        <code>${esc(p.cmdline || '')}</code>
                        ${!p.adoptable && p.adopt_hint ? `<br>${esc(p.adopt_hint)}` : ''}
                    </td></tr>`).join('')}
                </tbody></table></div>
                <div class="form-hint">«Остановить» без отключения скрипта
                    действует до перезагрузки: скрипт поднимет процесс снова.</div>`;
        }
        return `<div class="card"><div class="card-title">Запущенные не из GUI</div>
            <div class="card-body">${body}</div></div>`;
    }

    function _renderScripts(list) {
        let body;
        if (!list.length) {
            body = `<span class="text-muted">Сторонних init-скриптов движков не найдено.</span>`;
        } else {
            body = `<div class="table-wrap" style="overflow-x:auto;"><table class="table"><thead><tr>
                <th>Скрипт</th><th>Движок</th><th>Интерфейсы</th>
                <th>Автозапуск</th><th></th></tr></thead><tbody>
                ${list.map(s => `<tr>
                    <td><code>${esc(s.path)}</code></td>
                    <td>${esc(TITLES[s.engine] || s.engine)}</td>
                    <td>${(s.ifaces || []).map(i => `<code>${esc(i)}</code>`).join(' ') || '—'}</td>
                    <td>${s.enabled
                        ? '<span class="text-warning">включён</span>'
                        : (s.gui_disabled ? 'отключён GUI' : 'выключен')}
                        ${(s.running_pids || []).length
                            ? `<br><span class="form-hint">работает: pid ${esc(s.running_pids.join(', '))}</span>` : ''}</td>
                    <td style="text-align:right;">
                        ${s.enabled
                            ? `<button class="btn btn-danger btn-sm" data-act="disable"
                                   data-path="${esc(s.path)}">Остановить и отключить</button>`
                            : (s.gui_disabled
                                ? `<button class="btn btn-sm" data-act="enable"
                                       data-path="${esc(s.path)}">Вернуть автозапуск</button>`
                                : '')}
                    </td></tr>`).join('')}
                </tbody></table></div>
                <div class="form-hint">Скрипт не удаляется: на Entware снимается
                    бит исполнения (rc.unslung запускает только исполняемые
                    <code>S*</code>), на OpenWrt — штатный <code>disable</code>.
                    Если обновление пакета вернёт автозапуск, GUI отключит его снова.
                    «Вернуть автозапуск» восстанавливает прежнее состояние.</div>`;
        }
        return `<div class="card"><div class="card-title">Init-скрипты движков</div>
            <div class="card-body">${body}</div></div>`;
    }

    function _renderExclusive(on) {
        return `<div class="card"><div class="card-title">Режим «туннелями владеет только GUI»</div>
            <div class="card-body">
                <label class="form-check">
                    <input type="checkbox" id="fs-exclusive" ${on ? 'checked' : ''}>
                    Отключать любые найденные сторонние скрипты движков и
                    останавливать сторонние процессы (проверка раз в минуту и
                    при старте GUI)
                </label>
                <div class="form-hint">Без этого режима GUI держит отключёнными
                    только те скрипты, которые вы отключили здесь сами.
                    Telegram-прокси через скрипт пакета <code>S99tg-ws-proxy</code>
                    GUI ведёт сам — его режим не трогает.</div>
            </div></div>`;
    }

    async function _onClick(e) {
        const btn = e.target.closest('button[data-act]');
        if (!btn || _busy) return;
        const act = btn.dataset.act;
        let url, body, question;
        if (act === 'adopt') {
            url = '/api/foreign/adopt';
            body = {engine: btn.dataset.engine, pid: Number(btn.dataset.pid)};
            question = ['Передать туннель GUI?',
                `Конфиг будет скопирован в профиль GUI, сторонний процесс
                 (pid ${esc(btn.dataset.pid)}) остановлен, его init-скрипт
                 отключён, туннель поднят силами GUI с автозапуском. Если GUI
                 не сможет его поднять, скрипт будет включён и запущен обратно.`];
        } else if (act === 'stop') {
            url = '/api/foreign/process/stop';
            body = {pid: Number(btn.dataset.pid)};
            question = ['Остановить процесс?',
                `Процесс ${esc(btn.dataset.pid)} будет завершён. Туннель, который
                 он держит, пропадёт.`];
        } else if (act === 'disable') {
            url = '/api/foreign/script/disable';
            body = {path: btn.dataset.path};
            question = ['Остановить и отключить скрипт?',
                `<code>${esc(btn.dataset.path)}</code> будет остановлен и больше
                 не запустится при загрузке. Туннель, который он поднимает,
                 пропадёт.`];
        } else if (act === 'enable') {
            url = '/api/foreign/script/enable';
            body = {path: btn.dataset.path};
        } else {
            return;
        }
        if (question) {
            const ok = await Confirm.show(question[0], question[1],
                                          {danger: act !== 'adopt'});
            if (!ok) return;
        }
        await _post(url, body, act === 'adopt');
    }

    async function _onChange(e) {
        if (e.target.id !== 'fs-exclusive') return;
        const on = e.target.checked;
        if (on) {
            const ok = await Confirm.show('Включить режим «только GUI»?',
                `Все найденные сторонние скрипты usque, sing-box, mihomo,
                 AmneziaWG и Opera Proxy будут отключены, а их процессы
                 остановлены — сейчас и при каждом обнаружении. Туннели,
                 которые вы хотите сохранить, сначала передайте GUI.`,
                {danger: true});
            if (!ok) { e.target.checked = false; return; }
        }
        await _post('/api/foreign/exclusive', {enabled: on}, false);
    }

    async function _post(url, body, adopt) {
        _busy = true;
        try {
            const r = await API.post(url, body);
            if (r && r.ok) {
                let msg = adopt ? `Туннель теперь под GUI: профиль «${r.name || ''}»` : 'Готово';
                if (r.warning) msg += ` (${r.warning})`;
                if ((r.still_running || []).length) {
                    msg += `; ещё работает pid ${r.still_running.join(', ')} — `
                        + 'его этот скрипт, похоже, не запускал, остановите отдельно';
                }
                Toast.success(msg);
            } else {
                Toast.error((r && r.error) || 'Не удалось');
            }
        } catch (err) {
            Toast.error('Ошибка: ' + (err && err.message || err));
        } finally {
            _busy = false;
            await _refresh();
        }
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    return { render, destroy };
})();
