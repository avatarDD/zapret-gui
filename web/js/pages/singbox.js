/**
 * singbox.js — Dashboard для sing-box.
 *
 * Список конфигов / активных инстансов, статус каждого,
 * кнопки up/down/restart, ссылки на «Конфиги» и «Установка».
 * Polling раз в 5 секунд (как awg_dashboard).
 */

const SingboxDashboardPage = (() => {

    let pollTimer = null;
    let configs = [];
    let env = null;
    let autostart = {};
    let busy = {};

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">sing-box — инстансы</h1>
                    <p class="page-description">
                        VLESS / Trojan / Hysteria2 / TUIC / Shadowsocks через
                        универсальный sing-box-движок.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox-configs'">
                        Конфиги
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox-setup'">
                        Установка
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SingboxDashboardPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div class="card" id="sb-summary" style="margin-bottom:16px;">
                <div class="card-title">Обзор</div>
                <div id="sb-summary-body" style="margin-top:8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div id="sb-instances"></div>
        `;
        refresh();
        startPolling();
    }

    function destroy() {
        stopPolling();
    }

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [envResp, cfgsResp, autoResp] = await Promise.all([
                API.get('/api/singbox/environment').catch(() => null),
                API.get('/api/singbox/configs').catch(() => null),
                API.get('/api/singbox/autostart').catch(() => null),
            ]);
            env       = envResp || null;
            configs   = (cfgsResp && cfgsResp.configs) || [];
            autostart = (autoResp && autoResp.status && autoResp.status.autostart) || {};
        } catch (err) {
            const box = document.getElementById('sb-summary-body');
            if (box) box.innerHTML =
                `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function refresh() {
        await loadAll();
        renderSummary();
        renderInstances();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(refresh, 5000);
    }
    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // ══════════════ summary ══════════════

    function renderSummary() {
        const body = document.getElementById('sb-summary-body');
        if (!body) return;

        if (!env) {
            body.innerHTML = `<div class="text-muted">Нет данных от сервера.</div>`;
            return;
        }

        const bin       = env.binary || {};
        const platform  = env.platform || {};
        const tun       = env.tun || {};
        const installed = !!bin.installed;
        const ready     = !!env.ready;
        const active = configs.filter(c => c.running).length;

        const installBtn = installed
            ? ''
            : `<button class="btn btn-primary btn-sm"
                       onclick="window.location.hash='singbox-setup'">
                  Установить sing-box
              </button>`;

        body.innerHTML = `
            <div style="display:flex; gap:24px; flex-wrap:wrap; font-size:13px;">
                <div>
                    <div class="text-muted" style="font-size:11px;">Платформа</div>
                    <strong>${escapeHtml(platform.kind || platform.name || '?')}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">sing-box</div>
                    <strong>${installed
                        ? escapeHtml(bin.version || 'установлен')
                        : '<span style="color:#e58;">не установлен</span>'}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">TUN</div>
                    <strong>${tun.available
                        ? 'доступен'
                        : '<span style="color:#e58;">нет</span>'}</strong>
                </div>
                <div>
                    <div class="text-muted" style="font-size:11px;">Конфиги</div>
                    <strong>${configs.length} <span class="text-muted">(активно ${active})</span></strong>
                </div>
                <div style="margin-left:auto; display:flex; gap:8px;">
                    ${installBtn}
                </div>
            </div>
        `;
    }

    // ══════════════ instances ══════════════

    function renderInstances() {
        const box = document.getElementById('sb-instances');
        if (!box) return;

        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <div class="text-muted">
                      Конфигов нет. Перейдите в раздел
                      <a href="#singbox-configs" style="text-decoration:underline;">Конфиги</a>,
                      создайте новый или импортируйте подписку.
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
                           onclick="SingboxDashboardPage.down('${escapeAttr(c.name)}')">
                       Остановить
                   </button>`
                : `<button class="btn btn-primary btn-sm" ${isBusy ? 'disabled' : ''}
                           onclick="SingboxDashboardPage.up('${escapeAttr(c.name)}')">
                       Запустить
                   </button>`;

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
                            ${escapeHtml(c.path)} · ${Math.round(c.size / 1024)} KB
                            ${autoOn ? ' · автозапуск' : ''}
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        ${upBtn}
                        <button class="btn btn-ghost btn-sm" ${isBusy ? 'disabled' : ''}
                                onclick="SingboxDashboardPage.restart('${escapeAttr(c.name)}')">
                            Restart
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="window.location.hash='singbox-configs?edit=${encodeURIComponent(c.name)}'">
                            Редактировать
                        </button>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    // ══════════════ actions ══════════════

    async function up(name) {
        await action(name, 'up');
    }
    async function down(name) {
        await action(name, 'down');
    }
    async function restart(name) {
        await action(name, 'restart');
    }

    async function action(name, op) {
        busy[name] = true;
        renderInstances();
        try {
            const r = await API.post(`/api/singbox/configs/${encodeURIComponent(name)}/${op}`);
            if (r && r.ok) {
                Toast.success(`${name}: ${op} OK`);
            } else {
                const err = (r && r.error) || 'ошибка';
                Toast.error(`${name}: ${err}`);
                if (r && r.log_tail) {
                    console.warn(`sing-box ${name} log tail:`, r.log_tail);
                }
            }
        } catch (e) {
            Toast.error(`${name}: ${e.message}`);
        } finally {
            busy[name] = false;
            await refresh();
        }
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
        up, down, restart,
    };
})();
