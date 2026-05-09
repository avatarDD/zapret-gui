/**
 * awg_dashboard.js — Dashboard для AmneziaWG.
 *
 * Показывает все конфиги/активные интерфейсы, статус каждого peer'а
 * (last handshake, RX/TX), кнопки up/down/restart. Обновляется раз
 * в 5 секунд.
 */

const AwgDashboardPage = (() => {

    let pollTimer = null;
    let configs = [];
    let interfaces = [];
    let busy = {};

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">AmneziaWG — туннели</h1>
                    <p class="page-description">
                        Состояние интерфейсов amneziawg-go и управление ими.
                    </p>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='awg-configs'">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                        Конфиги
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='awg-setup'">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <circle cx="12" cy="12" r="3"/>
                            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9 1.65 1.65 0 0 0 4.27 7.18l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6V3a2 2 0 0 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9V11a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                        </svg>
                        Установка
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="AwgDashboardPage.refresh()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="23 4 23 10 17 10"/>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                        Обновить
                    </button>
                </div>
            </div>

            <div class="card" id="awg-summary" style="margin-bottom: 16px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <rect x="3" y="3" width="7" height="9" rx="1"/>
                        <rect x="14" y="3" width="7" height="5" rx="1"/>
                        <rect x="14" y="12" width="7" height="9" rx="1"/>
                        <rect x="3" y="16" width="7" height="5" rx="1"/>
                    </svg>
                    Обзор
                </div>
                <div id="awg-summary-body" style="margin-top: 8px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <div id="awg-tunnels"></div>
        `;

        refresh();
        startPolling();
    }

    function destroy() {
        stopPolling();
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(refresh, 5000);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // ══════════════ data ══════════════

    async function refresh() {
        try {
            const [cfgsResp, ifsResp] = await Promise.all([
                API.get('/api/awg/configs'),
                API.get('/api/awg/interfaces'),
            ]);
            configs = cfgsResp.configs || [];
            interfaces = ifsResp.interfaces || [];
            renderBody();
        } catch (err) {
            const body = document.getElementById('awg-summary-body');
            if (body) body.innerHTML = `<div class="text-muted">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    function renderBody() {
        const ifaceByName = {};
        interfaces.forEach(i => { ifaceByName[i.name] = i; });

        // Сводка
        const totalCfg = configs.length;
        const activeCount = configs.filter(c => c.active).length;
        const peerCount = interfaces.reduce((s, i) => s + (i.peers || []).length, 0);
        const summary = document.getElementById('awg-summary-body');
        if (summary) {
            summary.innerHTML = `
                <div style="display: flex; gap: 24px; flex-wrap: wrap;">
                    <div><div class="text-muted" style="font-size:12px;">Конфигов</div>
                         <div style="font-size: 20px; font-weight: 600;">${totalCfg}</div></div>
                    <div><div class="text-muted" style="font-size:12px;">Активных туннелей</div>
                         <div style="font-size: 20px; font-weight: 600;">${activeCount}</div></div>
                    <div><div class="text-muted" style="font-size:12px;">Peers всего</div>
                         <div style="font-size: 20px; font-weight: 600;">${peerCount}</div></div>
                </div>
            `;
        }

        // Туннели
        const wrap = document.getElementById('awg-tunnels');
        if (!wrap) return;

        if (configs.length === 0 && interfaces.length === 0) {
            wrap.innerHTML = `
                <div class="card">
                    <div style="padding: 16px; text-align: center;">
                        <p>Конфигов пока нет.</p>
                        <a href="#awg-configs" class="btn btn-primary btn-sm">Создать первый</a>
                    </div>
                </div>`;
            return;
        }

        // Объединяем: конфиги + active-only интерфейсы (которые не имеют конфига)
        const cfgNames = new Set(configs.map(c => c.name));
        const orphanIfaces = interfaces.filter(i => !cfgNames.has(i.name));

        const cards = [];
        configs.forEach(c => {
            cards.push(renderTunnelCard(c, ifaceByName[c.name]));
        });
        orphanIfaces.forEach(i => {
            cards.push(renderTunnelCard({ name: i.name, active: i.active, orphan: true }, i));
        });
        wrap.innerHTML = cards.join('');
    }

    function renderTunnelCard(cfg, iface) {
        const active = !!(iface && iface.active);
        const peers = (iface && iface.peers) || [];
        const inUse = busy[cfg.name];

        const statusBadge = active
            ? `<span class="status-dot running"></span><span class="text-running">активен</span>`
            : `<span class="status-dot stopped"></span><span class="text-muted">остановлен</span>`;

        let peersHtml = '';
        if (active && peers.length > 0) {
            peersHtml = `
                <table class="table" style="margin-top: 8px; font-size: 12px;">
                    <thead>
                        <tr>
                            <th style="width: 35%;">Peer</th>
                            <th>Endpoint</th>
                            <th>AllowedIPs</th>
                            <th>Last handshake</th>
                            <th>RX / TX</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${peers.map(p => `
                            <tr>
                                <td title="${escapeHtml(p.public_key)}" style="font-family:monospace;">
                                    ${escapeHtml(shortKey(p.public_key))}
                                </td>
                                <td>${escapeHtml(p.endpoint || '—')}</td>
                                <td style="font-family:monospace;">${escapeHtml(p.allowed_ips || '—')}</td>
                                <td>${formatHandshake(p.latest_handshake)}</td>
                                <td>${formatBytes(p.rx_bytes)} / ${formatBytes(p.tx_bytes)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        } else if (active) {
            peersHtml = `<div class="text-muted" style="margin-top: 8px;">Peers ещё не зарегистрированы</div>`;
        }

        const orphan = cfg.orphan
            ? `<span class="badge badge-warning" style="margin-left: 8px;">без конфига</span>`
            : '';

        return `
            <div class="card" style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display:flex; align-items: center; gap: 8px;">
                        <strong>${escapeHtml(cfg.name)}</strong> ${orphan}
                        <span style="display:flex; gap: 6px; align-items: center; margin-left: 8px;">
                            ${statusBadge}
                        </span>
                    </div>
                    <div style="display:flex; gap: 6px;">
                        ${active
                            ? `<button class="btn btn-ghost btn-sm" ${inUse?'disabled':''}
                                       onclick="AwgDashboardPage.restart('${escapeAttr(cfg.name)}')">Restart</button>
                               <button class="btn btn-ghost btn-sm" ${inUse?'disabled':''}
                                       onclick="AwgDashboardPage.down('${escapeAttr(cfg.name)}')">Stop</button>`
                            : (cfg.orphan
                                ? ''
                                : `<button class="btn btn-primary btn-sm" ${inUse?'disabled':''}
                                           onclick="AwgDashboardPage.up('${escapeAttr(cfg.name)}')">Start</button>`)
                        }
                        ${cfg.orphan
                            ? ''
                            : `<button class="btn btn-ghost btn-sm"
                                       onclick="window.location.hash='awg-configs?edit=${encodeURIComponent(cfg.name)}'">
                                   Редактировать
                               </button>`
                        }
                    </div>
                </div>
                ${peersHtml}
            </div>
        `;
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
        if (busy[name]) return;
        busy[name] = true;
        renderBody();
        try {
            const data = await API.post(`/api/awg/configs/${encodeURIComponent(name)}/${op}`);
            if (data.ok) {
                Toast.success(data.message || `${name}: ${op}`);
            } else {
                Toast.error(data.message || `Ошибка ${op}`);
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            busy[name] = false;
            await refresh();
        }
    }

    // ══════════════ helpers ══════════════

    function shortKey(k) {
        if (!k) return '';
        return k.length > 10 ? k.slice(0, 6) + '…' + k.slice(-4) : k;
    }

    function formatHandshake(ts) {
        if (!ts) return '—';
        const diff = Math.floor(Date.now() / 1000 - ts);
        if (diff < 0) return '—';
        if (diff < 60) return diff + ' сек назад';
        if (diff < 3600) return Math.floor(diff / 60) + ' мин назад';
        if (diff < 86400) return Math.floor(diff / 3600) + ' ч назад';
        return Math.floor(diff / 86400) + ' дн назад';
    }

    function formatBytes(n) {
        n = +n || 0;
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        if (n < 1024 * 1024 * 1024) return (n / 1048576).toFixed(1) + ' MB';
        return (n / 1073741824).toFixed(2) + ' GB';
    }

    function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    }

    function escapeAttr(s) {
        return String(s || '').replace(/'/g, '&#39;').replace(/"/g, '&quot;');
    }

    return { render, destroy, refresh, up, down, restart };
})();
