/**
 * mihomo.js — страница mihomo (Clash.Meta).
 *
 * Альтернативный прокси-движок рядом с sing-box (идея из XKeen).
 * Одна страница совмещает: обзор окружения + установку, список
 * инстансов с up/down/restart, и простой YAML-редактор конфигов.
 *
 * Бэкенд — /api/mihomo/* (зеркалит /api/singbox/*). Конфиги — clash-YAML.
 * Polling раз в 5 секунд.
 */

const MihomoPage = (() => {

    let pollTimer = null;
    let configs = [];
    let env = null;
    let autostart = {};
    let busy = {};
    let editing = null;   // {name, text} | null   (null = редактор закрыт)
    let installing = false;
    let installState = { status: 'idle', progress: 0, message: '' };
    let installTimer = null;

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">mihomo (Clash.Meta)${typeof Help !== 'undefined' ? Help.button('mihomo') : ''}</h1>
                    <p class="page-description">
                        Альтернативный прокси-движок: clash-YAML конфиги,
                        VLESS/Trojan/SS/Hysteria2/TUIC, GeoIP/GeoSite-роутинг.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.newConfig()">
                        + Конфиг
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div class="card" id="mh-summary" style="margin-bottom:16px;">
                <div class="card-title">Обзор</div>
                <div id="mh-summary-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div id="mh-editor"></div>
            <div id="mh-instances"></div>
        `;
        refresh();
        startPolling();
    }

    function destroy() {
        stopPolling();
        if (installTimer) { clearTimeout(installTimer); installTimer = null; }
    }

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [envResp, cfgsResp, autoResp] = await Promise.all([
                API.get('/api/mihomo/environment').catch(() => null),
                API.get('/api/mihomo/configs').catch(() => null),
                API.get('/api/mihomo/autostart').catch(() => null),
            ]);
            env       = envResp || null;
            configs   = (cfgsResp && cfgsResp.configs) || [];
            autostart = (autoResp && autoResp.status && autoResp.status.autostart) || {};
        } catch (err) {
            const box = document.getElementById('mh-summary-body');
            if (box) box.innerHTML =
                `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function refresh() {
        await loadAll();
        renderSummary();
        renderInstances();
        renderEditor();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            // Не дёргаем список во время редактирования — не сбиваем ввод.
            if (!editing) refresh();
        }, 5000);
    }
    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // ══════════════ summary ══════════════

    function renderSummary() {
        const body = document.getElementById('mh-summary-body');
        if (!body) return;
        if (!env) {
            body.innerHTML = `<div class="text-muted">Нет данных от сервера.</div>`;
            return;
        }
        const bin       = env.binary || {};
        const platform  = env.platform || {};
        const installed = !!bin.installed;
        const active = configs.filter(c => c.running).length;

        const installBtn = installed
            ? `<button class="btn btn-ghost btn-sm" ${installing ? 'disabled' : ''}
                       onclick="MihomoPage.install()">
                  ${installing ? 'Установка...' : 'Обновить mihomo'}
               </button>`
            : `<button class="btn btn-primary btn-sm" ${installing ? 'disabled' : ''}
                       onclick="MihomoPage.install()">
                  ${installing ? 'Установка...' : 'Установить mihomo'}
               </button>`;

        body.innerHTML = `
            <div style="display:flex; gap:24px; flex-wrap:wrap; font-size:13px;">
                <div>
                    <div class="text-muted" style="font-size:11px;">Платформа</div>
                    <strong>${escapeHtml(platform.kind || platform.name || '?')}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">mihomo</div>
                    <strong>${installed
                        ? escapeHtml(bin.version || 'установлен')
                        : '<span style="color:#e58;">не установлен</span>'}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">Конфиги</div>
                    <strong>${configs.length} <span class="text-muted">(активно ${active})</span></strong>
                </div>
                <div style="margin-left:auto; display:flex; gap:8px;">
                    ${installBtn}
                </div>
            </div>
            ${renderInstallProgress()}
        `;
    }

    function renderInstallProgress() {
        const st = installState;
        const show = installing || st.status === 'done' || st.status === 'error';
        if (!show) return '';
        const pct = Math.max(0, Math.min(100, st.progress || 0));
        const barColor = st.status === 'error' ? 'var(--error)' : 'var(--accent)';
        return `
            <div style="margin-top:12px;">
                <div style="display:flex; justify-content:space-between; font-size:12px;">
                    <span class="text-muted">${escapeHtml(st.message || 'Установка mihomo…')}</span>
                    <span class="text-muted">${pct}%</span>
                </div>
                <div style="height:6px; background:var(--bg-input); border-radius:4px; overflow:hidden; margin-top:4px;">
                    <div style="height:100%; width:${pct}%; background:${barColor}; transition:width .3s;"></div>
                </div>
            </div>`;
    }

    // ══════════════ instances ══════════════

    function renderInstances() {
        const box = document.getElementById('mh-instances');
        if (!box) return;
        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <div class="text-muted">
                      Конфигов нет. Нажмите «+ Конфиг» и вставьте clash-YAML.
                    </div>
                </div>`;
            return;
        }
        box.innerHTML = configs.map(c => {
            const active = !!c.running;
            const autoOn = !!autostart[c.name];
            const isBusy = !!busy[c.name];
            const upBtn = active
                ? `<button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="MihomoPage.down('${escapeAttr(c.name)}')">Остановить</button>`
                : `<button class="btn btn-primary btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="MihomoPage.up('${escapeAttr(c.name)}')">Запустить</button>`;
            return `
            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:15px; font-weight:600;">
                            ${escapeHtml(c.name)}
                            ${active
                                ? '<span style="color:#39c45e; font-size:11px; margin-left:6px;">● running</span>'
                                : '<span class="text-muted" style="font-size:11px; margin-left:6px;">● stopped</span>'}
                        </div>
                        <div class="text-muted" style="font-size:11px;">
                            ${escapeHtml(c.path)} · ${Math.round((c.size||0) / 1024)} KB
                            ${autoOn ? ' · автозапуск' : ''}
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        ${upBtn}
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="MihomoPage.restart('${escapeAttr(c.name)}')">Restart</button>
                        <label class="text-muted" style="font-size:11px; display:flex; align-items:center; gap:4px;">
                            <input type="checkbox" ${autoOn ? 'checked' : ''}
                                   onchange="MihomoPage.toggleAuto('${escapeAttr(c.name)}', this.checked)">
                            автозапуск
                        </label>
                        <button class="btn btn-ghost btn-sm"
                                onclick="MihomoPage.edit('${escapeAttr(c.name)}')">Редактировать</button>
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="MihomoPage.del('${escapeAttr(c.name)}')">Удалить</button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    // ══════════════ editor ══════════════

    const SAMPLE_YAML =
`mixed-port: 7890
mode: rule
proxies:
  - name: "my-vless"
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: tcp
    tls: true
    servername: example.com
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["my-vless"]
rules:
  - MATCH,PROXY
`;

    function renderEditor() {
        const box = document.getElementById('mh-editor');
        if (!box) return;
        if (!editing) { box.innerHTML = ''; return; }
        const isNew = editing.isNew;
        box.innerHTML = `
            <div class="card" style="margin-bottom:16px; border:1px solid var(--border, #333);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="card-title">${isNew ? 'Новый конфиг' : 'Редактирование: ' + escapeHtml(editing.name)}</div>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoPage.closeEditor()">Закрыть</button>
                </div>
                ${isNew ? `
                <div style="margin-top:8px;">
                    <label class="text-muted" style="font-size:12px;">Имя (A-Za-z0-9._-)</label>
                    <input id="mh-edit-name" class="input" style="width:100%; max-width:320px;"
                           value="${escapeAttr(editing.name)}" placeholder="например: home">
                </div>` : ''}
                <textarea id="mh-edit-text" spellcheck="false"
                          style="width:100%; min-height:340px; margin-top:8px; font-family:monospace;
                                 font-size:12px; white-space:pre; overflow:auto;">${escapeHtml(editing.text)}</textarea>
                <div style="display:flex; gap:8px; margin-top:8px;">
                    <button class="btn btn-primary btn-sm" onclick="MihomoPage.save()">Сохранить</button>
                    ${!isNew ? `<button class="btn btn-ghost btn-sm"
                        onclick="MihomoPage.validate()">Проверить (mihomo -t)</button>` : ''}
                </div>
            </div>
        `;
    }

    function newConfig() {
        editing = { name: '', text: SAMPLE_YAML, isNew: true };
        renderEditor();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function edit(name) {
        try {
            const r = await API.get(`/api/mihomo/configs/${encodeURIComponent(name)}`);
            if (!r || !r.ok) { Toast.error((r && r.error) || 'не найден'); return; }
            editing = { name, text: r.text || '', isNew: false };
            renderEditor();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (e) { Toast.error(e.message); }
    }

    function closeEditor() {
        editing = null;
        renderEditor();
        refresh();
    }

    async function save() {
        const ta = document.getElementById('mh-edit-text');
        if (!ta) return;
        const text = ta.value;
        let name = editing.name;
        if (editing.isNew) {
            const ni = document.getElementById('mh-edit-name');
            name = (ni && ni.value || '').trim();
            if (!name) { Toast.error('Укажите имя конфига'); return; }
        }
        try {
            let r;
            if (editing.isNew) {
                r = await API.post('/api/mihomo/configs', { name, text });
            } else {
                r = await API.put(`/api/mihomo/configs/${encodeURIComponent(name)}`, { text });
            }
            if (r && r.ok) {
                Toast.success('Сохранено');
                if (r.warnings && r.warnings.length) {
                    Toast.error('Предупреждения: ' + r.warnings.join('; '));
                }
                editing = null;
                renderEditor();
                await refresh();
            } else {
                Toast.error((r && r.error) || 'ошибка сохранения');
            }
        } catch (e) { Toast.error(e.message); }
    }

    async function validate() {
        if (!editing || editing.isNew) return;
        try {
            const r = await API.post(`/api/mihomo/configs/${encodeURIComponent(editing.name)}/validate`);
            if (r && r.ok) Toast.success('Конфиг валиден');
            else Toast.error('mihomo -t: ' + ((r && (r.stderr || r.error)) || 'ошибка'));
        } catch (e) { Toast.error(e.message); }
    }

    async function del(name) {
        if (!confirm(`Удалить конфиг «${name}»?`)) return;
        try {
            const r = await API.delete(`/api/mihomo/configs/${encodeURIComponent(name)}`);
            if (r && r.ok) { Toast.success('Удалён'); await refresh(); }
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
    }

    // ══════════════ actions ══════════════

    async function up(name)      { await action(name, 'up'); }
    async function down(name)    { await action(name, 'down'); }
    async function restart(name) { await action(name, 'restart'); }

    async function action(name, op) {
        busy[name] = true;
        renderInstances();
        try {
            const r = await API.post(`/api/mihomo/configs/${encodeURIComponent(name)}/${op}`);
            if (r && r.ok) Toast.success(`${name}: ${op} OK`);
            else {
                Toast.error(`${name}: ${(r && r.error) || 'ошибка'}`);
                if (r && r.log_tail) console.warn(`mihomo ${name} log:`, r.log_tail);
            }
        } catch (e) { Toast.error(`${name}: ${e.message}`); }
        finally { busy[name] = false; await refresh(); }
    }

    async function toggleAuto(name, enabled) {
        try {
            const r = await API.post(`/api/mihomo/autostart/${encodeURIComponent(name)}`,
                                     { enabled });
            if (r && r.ok) Toast.success(`автозапуск ${name}: ${enabled ? 'вкл' : 'выкл'}`);
            else Toast.error((r && r.error) || 'ошибка');
        } catch (e) { Toast.error(e.message); }
        finally { await refresh(); }
    }

    async function install() {
        if (installing) return;
        installing = true;
        installState = { status: 'starting', progress: 0,
                         message: 'Запуск установки mihomo…' };
        renderSummary();
        try {
            const r = await API.post('/api/mihomo/install', {});
            if (r && r.ok && !r.in_progress) {
                // Успели синхронно (быстрый канал/кэш).
                installState = { status: 'done', progress: 100,
                                 message: 'Установлено' };
                installing = false;
                renderSummary();
                Toast.success('mihomo установлен: ' + (r.version || ''));
                await refresh();
                return;
            }
            if (r && r.error && !r.in_progress) {
                installing = false;
                installState = { status: 'error', progress: 0, message: r.error };
                renderSummary();
                Toast.error(r.error);
                return;
            }
            // Идёт в фоне — поллим прогресс.
            pollInstall();
        } catch (e) {
            installing = false;
            installState = { status: 'error', progress: 0, message: e.message };
            renderSummary();
            Toast.error(e.message);
        }
    }

    function pollInstall() {
        if (installTimer) clearTimeout(installTimer);
        installTimer = setTimeout(async () => {
            try {
                const r = await API.get('/api/mihomo/install/status');
                if (r && r.progress) installState = r.progress;
                renderSummary();
                const s = installState.status;
                if (s === 'done' || s === 'installed' || s === 'idle') {
                    installing = false;
                    renderSummary();
                    Toast.success('mihomo установлен');
                    await refresh();          // обновит обзор/версию без перезагрузки страницы
                    return;
                }
                if (s === 'error') {
                    installing = false;
                    renderSummary();
                    Toast.error(installState.message || 'ошибка установки');
                    return;
                }
                pollInstall();                 // продолжаем поллить
            } catch (e) {
                installing = false;
                renderSummary();
                Toast.error(e.message);
            }
        }, 1200);
    }

    // ══════════════ helpers ══════════════

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escapeAttr(s) {
        return escapeHtml(s).replace(/"/g, '&quot;');
    }

    return {
        render, destroy, refresh,
        up, down, restart, install, toggleAuto,
        newConfig, edit, closeEditor, save, validate, del,
    };
})();
