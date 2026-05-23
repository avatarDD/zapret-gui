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
    let autostart = { interfaces: {}, script_installed: false, script_path: '' };
    let keeneticRouting = null;
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
            <div id="awg-keenetic-routing"></div>
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
            const [cfgsResp, ifsResp, autoResp, envResp] = await Promise.all([
                API.get('/api/awg/configs'),
                API.get('/api/awg/interfaces'),
                API.get('/api/awg/autostart').catch(() => ({ status: {} })),
                API.get('/api/awg/environment').catch(() => null),
            ]);
            configs = cfgsResp.configs || [];
            interfaces = ifsResp.interfaces || [];
            autostart = (autoResp && autoResp.status) || { interfaces: {} };
            if (!autostart.interfaces) autostart.interfaces = {};
            keeneticRouting = (envResp && envResp.keenetic_routing) || null;
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
        const autoCount = Object.values(autostart.interfaces || {}).filter(Boolean).length;
        const scriptInstalled = !!autostart.script_installed;
        const summary = document.getElementById('awg-summary-body');
        if (summary) {
            const scriptInfo = scriptInstalled
                ? `<span class="text-running">установлен</span>${autostart.script_path ? ` <span class="text-muted" style="font-size:11px;">(${escapeHtml(autostart.script_path)})</span>` : ''}`
                : `<span class="text-muted">не установлен</span>`;
            summary.innerHTML = `
                <div style="display: flex; gap: 24px; flex-wrap: wrap; align-items: flex-end;">
                    <div><div class="text-muted" style="font-size:12px;">Конфигов</div>
                         <div style="font-size: 20px; font-weight: 600;">${totalCfg}</div></div>
                    <div><div class="text-muted" style="font-size:12px;">Активных туннелей</div>
                         <div style="font-size: 20px; font-weight: 600;">${activeCount}</div></div>
                    <div><div class="text-muted" style="font-size:12px;">Peers всего</div>
                         <div style="font-size: 20px; font-weight: 600;">${peerCount}</div></div>
                    <div><div class="text-muted" style="font-size:12px;">Автозапуск</div>
                         <div style="font-size: 14px;">${autoCount} интерф., скрипт: ${scriptInfo}</div></div>
                    <div style="margin-left:auto; display:flex; gap:6px;">
                        ${scriptInstalled
                            ? `<button class="btn btn-ghost btn-sm" onclick="AwgDashboardPage.regenerateScript()">Пересоздать скрипт</button>
                               <button class="btn btn-ghost btn-sm" onclick="AwgDashboardPage.removeScript()">Удалить скрипт</button>`
                            : `<button class="btn btn-ghost btn-sm" ${autoCount===0?'disabled title="Включите autostart хотя бы у одного интерфейса"':''}
                                       onclick="AwgDashboardPage.installScript()">Установить init-скрипт</button>`}
                    </div>
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
        // Сопоставление по реальному имени интерфейса (cfg.iface), а не
        // только по имени файла — конфиги вида `awg0-opkgtun0.conf` для
        // интерфейса `opkgtun0` должны находить свой активный туннель.
        const claimedIfaces = new Set();
        configs.forEach(c => {
            if (c.iface) claimedIfaces.add(c.iface);
            claimedIfaces.add(c.name);
        });
        const orphanIfaces = interfaces.filter(i => !claimedIfaces.has(i.name));

        const cards = [];
        configs.forEach(c => {
            // Берём статус по фактическому имени интерфейса, если оно
            // отличается от имени конфига.
            const ifaceData = ifaceByName[c.iface] || ifaceByName[c.name];
            cards.push(renderTunnelCard(c, ifaceData));
        });
        orphanIfaces.forEach(i => {
            cards.push(renderTunnelCard({ name: i.name, active: i.active, orphan: true }, i));
        });
        wrap.innerHTML = cards.join('');

        renderKeeneticRouting();
    }

    function renderKeeneticRouting() {
        const wrap = document.getElementById('awg-keenetic-routing');
        if (!wrap) return;
        const k = keeneticRouting;
        if (!k || !k.available) {
            wrap.innerHTML = '';
            return;
        }
        const block = (title, body) => body
            ? `<details style="margin-top: 8px;">
                   <summary style="cursor:pointer; color: var(--text-secondary); font-size: 13px;">${escapeHtml(title)}</summary>
                   <pre style="margin-top: 6px; padding: 8px; background: var(--bg-input);
                                border-radius: var(--radius-sm); font-size: 11px;
                                max-height: 240px; overflow: auto;">${escapeHtml(body)}</pre>
               </details>`
            : '';
        wrap.innerHTML = `
            <div class="card" style="margin-top: 16px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M6 3v12"/><circle cx="6" cy="18" r="3"/>
                        <circle cx="18" cy="6" r="3"/><path d="M18 9v12"/>
                    </svg>
                    Маршрутизация Keenetic (NDM)
                </div>
                <div style="margin-top: 4px; font-size: 12px; color: var(--text-muted);">
                    Снимок текущих настроек штатного GUI Keenetic. AWG может конфликтовать
                    с этими политиками и маршрутами — проверьте, если что-то работает не так.
                </div>
                ${block('Политики (show ip policy)', k.policy)}
                ${block('Маршруты (show ip route)', k.routes)}
                ${block('Интерфейсы (show interface)', k.interfaces)}
            </div>
        `;
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
        const ifaceLabel = (cfg.iface && cfg.iface !== cfg.name)
            ? `<span class="text-muted" style="margin-left: 8px; font-size: 12px;">→ iface <span style="font-family:monospace;">${escapeHtml(cfg.iface)}</span></span>`
            : '';

        const autoOn = !!(autostart.interfaces || {})[cfg.name];
        const autoToggle = cfg.orphan
            ? ''
            : `<label style="display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer;"
                       title="Поднимать этот интерфейс при загрузке системы">
                   <input type="checkbox" ${autoOn?'checked':''} ${inUse?'disabled':''}
                          onchange="AwgDashboardPage.toggleAutostart('${escapeAttr(cfg.name)}', this.checked)">
                   автозапуск
               </label>`;

        return `
            <div class="card" style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display:flex; align-items: center; gap: 8px;">
                        <strong>${escapeHtml(cfg.name)}</strong> ${orphan} ${ifaceLabel}
                        <span style="display:flex; gap: 6px; align-items: center; margin-left: 8px;">
                            ${statusBadge}
                        </span>
                    </div>
                    <div style="display:flex; gap: 12px; align-items: center;">
                        ${autoToggle}
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
                            <button class="btn btn-ghost btn-sm"
                                    title="Снимок awg show + ip rule/route + последние логи — для диагностики проблем с маршрутизацией"
                                    onclick="AwgDashboardPage.diagnostics('${escapeAttr(cfg.name)}')">
                                Диагностика
                            </button>
                            ${cfg.orphan
                                ? ''
                                : `<button class="btn btn-ghost btn-sm"
                                           onclick="window.location.hash='awg-configs?edit=${encodeURIComponent(cfg.name)}'">
                                       Редактировать
                                   </button>`
                            }
                        </div>
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

    async function diagnostics(name) {
        if (busy[name]) return;
        busy[name] = true;
        try {
            const data = await API.get(
                `/api/awg/configs/${encodeURIComponent(name)}/diagnostics`
            );
            if (!data || !data.ok) {
                Toast.error((data && data.error) || 'Ошибка диагностики');
                return;
            }
            showDiagnosticsModal(name, data.diagnostics || {});
        } catch (err) {
            Toast.error(err.message);
        } finally {
            busy[name] = false;
        }
    }

    function showDiagnosticsModal(name, d) {
        const text = formatDiagnostics(d);

        // Минимальный модал — оверлей + контент, без зависимостей.
        const overlay = document.createElement('div');
        overlay.style.cssText =
            'position:fixed;inset:0;background:rgba(0,0,0,0.55);' +
            'display:flex;align-items:center;justify-content:center;' +
            'z-index:10000;padding:24px;';
        overlay.addEventListener('click', e => {
            if (e.target === overlay) document.body.removeChild(overlay);
        });

        const box = document.createElement('div');
        box.style.cssText =
            'background:var(--bg-card,#1f1f1f);color:var(--text,#eaeaea);' +
            'max-width:1000px;width:100%;max-height:85vh;' +
            'display:flex;flex-direction:column;border-radius:8px;' +
            'box-shadow:0 8px 28px rgba(0,0,0,0.5);overflow:hidden;';

        const header = document.createElement('div');
        header.style.cssText =
            'padding:12px 16px;border-bottom:1px solid var(--border,#333);' +
            'display:flex;justify-content:space-between;align-items:center;gap:12px;';
        header.innerHTML =
            '<strong style="font-size:14px;">Диагностика AWG: ' +
            escapeHtml(name) + '</strong>' +
            '<div style="display:flex;gap:8px;">' +
                '<button class="btn btn-ghost btn-sm" id="awgDiagCopy">Копировать</button>' +
                '<button class="btn btn-ghost btn-sm" id="awgDiagClose">Закрыть</button>' +
            '</div>';

        const body = document.createElement('pre');
        body.style.cssText =
            'margin:0;padding:14px 16px;overflow:auto;flex:1;' +
            'background:var(--bg-input,#111);font-family:ui-monospace,' +
            'SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.5;' +
            'white-space:pre-wrap;word-break:break-word;';
        body.textContent = text;

        box.appendChild(header);
        box.appendChild(body);
        overlay.appendChild(box);
        document.body.appendChild(overlay);

        document.getElementById('awgDiagClose').onclick =
            () => document.body.removeChild(overlay);
        document.getElementById('awgDiagCopy').onclick = async () => {
            try {
                await navigator.clipboard.writeText(text);
                Toast.success('Скопировано');
            } catch {
                // Фолбэк через execCommand
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); Toast.success('Скопировано'); }
                catch { Toast.error('Не удалось скопировать'); }
                document.body.removeChild(ta);
            }
        };
    }

    function formatDiagnostics(d) {
        const lines = [];
        const push = (label, val) => {
            lines.push('── ' + label + ' ──');
            lines.push(val == null || val === '' ? '(пусто)' : String(val).trimEnd());
            lines.push('');
        };

        lines.push('zapret-gui AWG diagnostics');
        lines.push('gui_ver:  ' + (d.gui_version || '?'));
        lines.push('config:   ' + (d.name || ''));
        lines.push('iface:    ' + (d.iface || ''));
        lines.push('table_id: ' + (d.table_id || ''));
        lines.push('active:   ' + (d.active ? 'yes' : 'no'));
        if (d.platform) {
            lines.push('platform: ' + (d.platform.name || '?') +
                       '  run_dir=' + (d.platform.run_dir || '?'));
        }
        if (d.binaries) {
            const b = d.binaries;
            lines.push('awg:      ' + (b.awg || '?') +
                       '  version=' + (b.awg_version || '?'));
            lines.push('amneziawg-go: ' + (b.amneziawg_go || '?') +
                       '  version=' + (b.amneziawg_go_version || '?'));
        }
        if (d.i1_lengths) {
            const il = d.i1_lengths;
            lines.push('I1 config bytes: ' + il.config_bytes +
                       '   I1 in awg show bytes: ' + il.show_bytes +
                       (il.bytes_match
                           ? '   bytes MATCH ✓'
                           : (il.in_awg_show
                                ? '   bytes MISMATCH ✗ — daemon altered I1!'
                                : '   I1 NOT echoed by daemon'))
            );
            if (il.config_prefix || il.show_prefix) {
                lines.push('  config[0..32]: ' + (il.config_prefix || ''));
                lines.push('  show  [0..32]: ' + (il.show_prefix   || ''));
            }
        }
        if (d.errors && d.errors.length) {
            lines.push('errors:   ' + d.errors.join('; '));
        }
        lines.push('');

        push('config file on disk (raw .conf as read by parse_conf)',
             d.config_file_text);
        push('rendered setconf (what we send to `awg setconf`)',
             d.setconf_text);
        push('awg show', d.awg_show);
        push('ip -d link show ' + (d.iface || ''), d.link);
        push('ip addr show ' + (d.iface || ''), d.addr);

        if (d.interface_state) {
            const ifs = d.interface_state.interface || {};
            const peers = d.interface_state.peers || [];
            lines.push('── interface (parsed) ──');
            lines.push('fwmark:     ' + (ifs.fwmark || '(off)'));
            lines.push('listen_port:' + (ifs.listen_port || ''));
            lines.push('public_key: ' + (ifs.public_key || ''));
            peers.forEach((p, i) => {
                lines.push('peer[' + i + ']:');
                lines.push('  endpoint:           ' + (p.endpoint || ''));
                lines.push('  allowed_ips:        ' + (p.allowed_ips || ''));
                lines.push('  latest_handshake:   ' + (p.latest_handshake || ''));
                lines.push('  rx/tx bytes:        ' +
                           (p.rx_bytes || 0) + ' / ' + (p.tx_bytes || 0));
            });
            lines.push('');
        }

        push('ip -4 rule list', d.rules && d.rules.v4);
        push('ip -6 rule list', d.rules && d.rules.v6);
        push('ip -4 route show table ' + (d.table_id || '?'),
             d.routes && d.routes.table_v4);
        push('ip -6 route show table ' + (d.table_id || '?'),
             d.routes && d.routes.table_v6);
        push('ip -4 route show table main', d.routes && d.routes.main_v4);
        push('ip -6 route show table main', d.routes && d.routes.main_v6);

        if (d.endpoint_routes && d.endpoint_routes.length) {
            lines.push('── ip route get <peer endpoint> ──');
            d.endpoint_routes.forEach(er => {
                lines.push('endpoint ' + er.endpoint + ' → ' + er.ip +
                           ' (' + er.family + ')');
                lines.push('  ' + (er.route || ''));
            });
            lines.push('');
        }

        if (d.last_up) {
            const lu = d.last_up;
            const savedTs = lu.saved_at
                ? new Date(lu.saved_at * 1000).toISOString()
                : '?';
            lines.push('════ LAST UP SNAPSHOT (saved at ' + savedTs + ') ════');
            lines.push('Состояние, снятое сразу после последнего `up` — для');
            lines.push('диагностики «после обвала», когда iface уже опущен.');
            lines.push('');
            push('  last_up: setconf actually sent', lu.setconf_text);
            push('  last_up: awg show',    lu.awg_show);
            push('  last_up: ip -4 rule',  lu.rules && lu.rules.v4);
            push('  last_up: ip -6 rule',  lu.rules && lu.rules.v6);
            push('  last_up: table ' + (lu.table_id || '?') + ' v4',
                 lu.routes && lu.routes.table_v4);
            push('  last_up: table ' + (lu.table_id || '?') + ' v6',
                 lu.routes && lu.routes.table_v6);
        }

        if (d.log_tail && d.log_tail.length) {
            lines.push('── log tail (awg/routing, последние ' +
                       d.log_tail.length + ') ──');
            d.log_tail.forEach(e => {
                const ts = e.timestamp
                    ? new Date(e.timestamp * 1000).toISOString()
                    : '?';
                lines.push('[' + ts + '] ' + (e.level || '') +
                           ' [' + (e.source || '') + '] ' +
                           (e.message || ''));
            });
        }
        return lines.join('\n');
    }

    async function toggleAutostart(name, enabled) {
        if (busy[name]) return;
        busy[name] = true;
        try {
            const data = await API.post(
                `/api/awg/autostart/${encodeURIComponent(name)}`,
                { enabled: !!enabled }
            );
            if (data && data.ok) {
                Toast.success(enabled
                    ? `${name}: автозапуск включён`
                    : `${name}: автозапуск выключен`);
            } else {
                Toast.error((data && data.error) || 'Не удалось изменить флаг');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            busy[name] = false;
            await refresh();
        }
    }

    async function installScript() {
        try {
            const data = await API.post('/api/awg/autostart/install');
            if (data.ok) Toast.success(data.message || 'Скрипт установлен');
            else Toast.error(data.error || 'Ошибка установки');
        } catch (err) {
            Toast.error(err.message);
        } finally {
            await refresh();
        }
    }

    async function removeScript() {
        if (!confirm('Удалить init-скрипт автозапуска AWG?')) return;
        try {
            const data = await API.post('/api/awg/autostart/remove');
            if (data.ok) Toast.success(data.message || 'Скрипт удалён');
            else Toast.error(data.error || 'Ошибка удаления');
        } catch (err) {
            Toast.error(err.message);
        } finally {
            await refresh();
        }
    }

    async function regenerateScript() {
        try {
            const data = await API.post('/api/awg/autostart/regenerate');
            if (data.ok) Toast.success(data.message || 'Скрипт пересоздан');
            else Toast.error(data.error || 'Ошибка');
        } catch (err) {
            Toast.error(err.message);
        } finally {
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

    return {
        render, destroy, refresh, up, down, restart, diagnostics,
        toggleAutostart, installScript, removeScript, regenerateScript,
    };
})();
