/**
 * diagnostics.js — Страница «Диагностика».
 *
 * Карточки сервисов (YouTube, Discord, …) с проверкой доступности,
 * системная информация, firewall, конфликты nfqws/tpws.
 * Ручная проверка каждого сервиса + «Проверить все».
 */

const DiagnosticsPage = (() => {
    /* ───────── state ───────── */
    let services = {};          // описание сервисов от API
    let serviceResults = {};    // результаты проверок
    let checking = {};          // { service_name: true } — идёт проверка
    let checkAllRunning = false;
    let systemInfo = null;
    let firewallInfo = null;
    let conflictsInfo = null;

    /* ──────── service icons (SVG) ──────── */
    const SVC_ICONS = {
        youtube:   '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.9 31.9 0 0 0 0 12a31.9 31.9 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.6 9.4.6 9.4.6s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.9 31.9 0 0 0 24 12a31.9 31.9 0 0 0-.5-5.8zM9.6 15.6V8.4L15.8 12l-6.2 3.6z"/></svg>',
        discord:   '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M20.3 4.4a19.6 19.6 0 0 0-4.9-1.5 14.5 14.5 0 0 0-.6 1.3 18 18 0 0 0-5.6 0 14.5 14.5 0 0 0-.7-1.3A19.6 19.6 0 0 0 3.7 4.4 20.5 20.5 0 0 0 .1 16.5a19.7 19.7 0 0 0 6 3 14.2 14.2 0 0 0 1.2-2 12.8 12.8 0 0 1-2-.9l.5-.4a14 14 0 0 0 12.1 0l.5.4a12.8 12.8 0 0 1-2 .9 14.2 14.2 0 0 0 1.2 2 19.7 19.7 0 0 0 6-3A20.5 20.5 0 0 0 20.3 4.4zM8 13.9c-1 0-1.9-1-1.9-2.1s.8-2.1 1.9-2.1 2 1 1.9 2.1c0 1.2-.8 2.1-1.9 2.1zm8 0c-1 0-1.9-1-1.9-2.1s.8-2.1 1.9-2.1 2 1 1.9 2.1c0 1.2-.8 2.1-1.9 2.1z"/></svg>',
        telegram:  '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm4.9 6.8l-1.7 7.8c-.1.5-.5.7-.9.4l-2.5-1.8-1.2 1.2c-.1.1-.3.2-.5.2l.2-2.5 4.7-4.2c.2-.2 0-.3-.3-.1L8.8 13l-2.4-.8c-.5-.2-.5-.5.1-.7l9.4-3.6c.5-.1.8.1.7.7l.3.2z"/></svg>',
        instagram: '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M12 2.2c2.7 0 3 0 4.1.1 1 0 1.5.2 1.9.4.5.2.8.4 1.1.7.3.3.6.7.7 1.1.2.4.3.9.4 1.9 0 1 .1 1.4.1 4.1s0 3-.1 4.1c0 1-.2 1.5-.4 1.9-.2.5-.4.8-.7 1.1-.3.3-.7.6-1.1.7-.4.2-.9.3-1.9.4-1 0-1.4.1-4.1.1s-3 0-4.1-.1c-1 0-1.5-.2-1.9-.4a3.3 3.3 0 0 1-1.1-.7c-.3-.3-.6-.7-.7-1.1-.2-.4-.3-.9-.4-1.9 0-1-.1-1.4-.1-4.1s0-3 .1-4.1c0-1 .2-1.5.4-1.9.2-.5.4-.8.7-1.1.3-.3.7-.6 1.1-.7.4-.2.9-.3 1.9-.4 1 0 1.4-.1 4.1-.1zM12 0C9.3 0 8.9 0 7.9.1c-1 0-1.7.2-2.3.5a4.6 4.6 0 0 0-1.7 1.1c-.5.5-.9 1-1.1 1.7-.3.6-.4 1.3-.5 2.3C2 6.6 2 7 2 9.7v4.6c0 2.7 0 3.1.1 4.1 0 1 .2 1.7.5 2.3.2.7.6 1.2 1.1 1.7.5.5 1 .9 1.7 1.1.6.3 1.3.4 2.3.5 1 0 1.4.1 4.1.1h.4c2.7 0 3.1 0 4.1-.1 1 0 1.7-.2 2.3-.5a4.6 4.6 0 0 0 1.7-1.1c.5-.5.9-1 1.1-1.7.3-.6.4-1.3.5-2.3 0-1 .1-1.4.1-4.1V9.7c0-2.7 0-3.1-.1-4.1 0-1-.2-1.7-.5-2.3a4.6 4.6 0 0 0-1.1-1.7c-.5-.5-1-.9-1.7-1.1-.6-.3-1.3-.4-2.3-.5C15.1 0 14.7 0 12 0zm0 5.8a6.2 6.2 0 1 0 0 12.4A6.2 6.2 0 0 0 12 5.8zm0 10.2a4 4 0 1 1 0-8 4 4 0 0 1 0 8zm6.4-10.5a1.4 1.4 0 1 0 0-2.9 1.4 1.4 0 0 0 0 2.9z"/></svg>',
        twitter:   '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M18.2 2.3h3.5l-7.6 8.7L23 21.7h-7l-5.5-7.2-6.3 7.2H.7l8.1-9.3L.4 2.3h7.2l5 6.6 5.7-6.6zm-1.2 17.5h1.9L7.1 4.2H5L17 19.8z"/></svg>',
        chatgpt:   '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M22.3 10.3a6.1 6.1 0 0 0-.5-5 6.2 6.2 0 0 0-6.7-3 6.1 6.1 0 0 0-4.6-2.1 6.2 6.2 0 0 0-5.9 4.3 6.1 6.1 0 0 0-4.1 3 6.2 6.2 0 0 0 .8 7.3 6.1 6.1 0 0 0 .5 5 6.2 6.2 0 0 0 6.7 3 6.1 6.1 0 0 0 4.6 2.1 6.2 6.2 0 0 0 5.9-4.3 6.1 6.1 0 0 0 4.1-3 6.2 6.2 0 0 0-.8-7.3z"/></svg>',
        claude:    '<svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4" fill="var(--bg-card)"/></svg>',
    };

    /* ──────── status helpers ──────── */
    const STATUS_LABELS = {
        ok:       'Доступен',
        partial:  'Частично',
        degraded: 'Проблемы',
        down:     'Недоступен',
        checking: 'Проверка…',
        pending:  'Ожидание',
    };
    const STATUS_COLORS = {
        ok:       'var(--success)',
        partial:  'var(--warning)',
        degraded: 'var(--warning)',
        down:     'var(--error)',
        checking: 'var(--accent)',
        pending:  'var(--text-muted)',
    };

    /* ═══════════════════ render ═══════════════════ */
    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Диагностика</h1>
                <p class="page-description">Проверка доступности сервисов, сети и системы</p>
            </div>

            <!-- Верхняя панель: кнопки -->
            <div class="diag-toolbar">
                <button class="btn btn-primary" id="diag-check-all" onclick="DiagnosticsPage.checkAll()">
                    <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    Проверить все
                </button>
                <button class="btn btn-ghost btn-sm" onclick="DiagnosticsPage.refreshSystem()">
                    Обновить систему
                </button>
            </div>

            <!-- Прогресс -->
            <div class="diag-progress hidden" id="diag-progress">
                <div class="diag-progress-track">
                    <div class="diag-progress-bar" id="diag-progress-bar"></div>
                </div>
                <span class="diag-progress-text" id="diag-progress-text">Проверка…</span>
            </div>

            <!-- Карточки сервисов -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="2" y1="12" x2="22" y2="12"/>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                    </svg>
                    Сервисы
                </div>
                <div class="diag-services-grid" id="diag-services-grid">
                    <div class="diag-loading">Загрузка списка сервисов…</div>
                </div>
            </div>

            <!-- Системная информация -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                        <line x1="8" y1="21" x2="16" y2="21"/>
                        <line x1="12" y1="17" x2="12" y2="21"/>
                    </svg>
                    Системная информация
                </div>
                <div id="diag-system-info">
                    <div class="diag-loading">Загрузка…</div>
                </div>
            </div>

            <!-- Firewall -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Firewall
                </div>
                <div id="diag-firewall">
                    <div class="diag-loading">Загрузка…</div>
                </div>
            </div>

            <!-- Конфликты -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    Конфликты процессов
                </div>
                <div id="diag-conflicts">
                    <div class="diag-loading">Загрузка…</div>
                </div>
            </div>

            <!-- Ручная проверка -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                    Ручная проверка
                </div>
                <div class="diag-manual-section">
                    <div class="diag-manual-row">
                        <div class="form-group" style="flex:1; min-width:180px">
                            <label class="form-label">Ping хоста</label>
                            <div class="diag-input-row">
                                <input class="form-input" id="diag-ping-host" placeholder="youtube.com" />
                                <button class="btn btn-ghost btn-sm" onclick="DiagnosticsPage.manualPing()">Ping</button>
                            </div>
                        </div>
                        <div class="form-group" style="flex:1; min-width:180px">
                            <label class="form-label">HTTP(S) проверка</label>
                            <div class="diag-input-row">
                                <input class="form-input" id="diag-http-url" placeholder="https://youtube.com" />
                                <button class="btn btn-ghost btn-sm" onclick="DiagnosticsPage.manualHttp()">Проверить</button>
                            </div>
                        </div>
                        <div class="form-group" style="flex:1; min-width:180px">
                            <label class="form-label">DNS resolve</label>
                            <div class="diag-input-row">
                                <input class="form-input" id="diag-dns-domain" placeholder="youtube.com" />
                                <button class="btn btn-ghost btn-sm" onclick="DiagnosticsPage.manualDns()">Resolve</button>
                            </div>
                        </div>
                    </div>
                    <pre class="diag-manual-output" id="diag-manual-output">Результаты проверок появятся здесь…</pre>
                </div>
            </div>
        `;

        // Загружаем данные
        loadServices();
        loadSystemInfo();
        loadFirewall();
        loadConflicts();
    }

    function destroy() {
        services = {};
        serviceResults = {};
        checking = {};
        checkAllRunning = false;
        systemInfo = null;
        firewallInfo = null;
        conflictsInfo = null;
    }

    /* ═══════════════════ Загрузка данных ═══════════════════ */

    async function loadServices() {
        try {
            const data = await API.get('/api/diagnostics/services');
            if (data.ok) {
                services = data.services;
                renderServicesGrid();
            }
        } catch (e) {
            document.getElementById('diag-services-grid').innerHTML =
                '<div class="diag-error">Ошибка загрузки сервисов</div>';
        }
    }

    async function loadSystemInfo() {
        try {
            const data = await API.get('/api/diagnostics/system');
            if (data.ok) {
                systemInfo = data.result;
                renderSystemInfo();
            }
        } catch (e) {
            document.getElementById('diag-system-info').innerHTML =
                '<div class="diag-error">Ошибка загрузки системной информации</div>';
        }
    }

    async function loadFirewall() {
        try {
            const data = await API.get('/api/diagnostics/firewall');
            if (data.ok) {
                firewallInfo = data.result;
                renderFirewall();
            }
        } catch (e) {
            document.getElementById('diag-firewall').innerHTML =
                '<div class="diag-error">Ошибка загрузки статуса firewall</div>';
        }
    }

    async function loadConflicts() {
        try {
            const data = await API.get('/api/diagnostics/conflicts');
            if (data.ok) {
                conflictsInfo = data.result;
                renderConflicts();
            }
        } catch (e) {
            document.getElementById('diag-conflicts').innerHTML =
                '<div class="diag-error">Ошибка загрузки</div>';
        }
    }

    /* ═══════════════════ Render: Сервисы ═══════════════════ */

    function renderServicesGrid() {
        const grid = document.getElementById('diag-services-grid');
        if (!grid) return;

        const names = Object.keys(services);
        if (names.length === 0) {
            grid.innerHTML = '<div class="diag-empty">Нет доступных сервисов</div>';
            return;
        }

        grid.innerHTML = names.map(name => {
            const svc = services[name];
            const result = serviceResults[name];
            const isChecking = checking[name];
            const status = isChecking ? 'checking' : (result ? result.status : 'pending');
            const statusLabel = STATUS_LABELS[status] || status;
            const statusColor = STATUS_COLORS[status] || 'var(--text-muted)';
            const icon = SVC_ICONS[name] || '';

            let detailsHtml = '';
            if (result && !isChecking) {
                detailsHtml = buildServiceDetails(result);
            }

            return `
                <div class="diag-service-card" id="svc-card-${name}" data-status="${status}">
                    <div class="diag-service-header">
                        <div class="diag-service-icon" style="color: ${statusColor}">${icon}</div>
                        <div class="diag-service-info">
                            <div class="diag-service-name">${_esc(svc.name)}</div>
                            <div class="diag-service-status" style="color: ${statusColor}">
                                ${isChecking ? '<span class="diag-spinner"></span>' : statusIndicator(status)}
                                ${statusLabel}
                            </div>
                        </div>
                        <button class="btn btn-ghost btn-sm diag-service-btn"
                                onclick="DiagnosticsPage.checkService('${name}')"
                                ${isChecking ? 'disabled' : ''}>
                            ${isChecking ? '…' : 'Проверить'}
                        </button>
                    </div>
                    <div class="diag-service-details" id="svc-details-${name}">
                        ${detailsHtml}
                    </div>
                </div>
            `;
        }).join('');
    }

    function statusIndicator(status) {
        if (status === 'ok')       return '<span class="diag-dot diag-dot-ok"></span>';
        if (status === 'partial')  return '<span class="diag-dot diag-dot-warn"></span>';
        if (status === 'degraded') return '<span class="diag-dot diag-dot-warn"></span>';
        if (status === 'down')     return '<span class="diag-dot diag-dot-err"></span>';
        return '<span class="diag-dot diag-dot-muted"></span>';
    }

    function buildServiceDetails(result) {
        if (!result || result.error) return '';
        const parts = [];

        // Ping
        if (result.ping) {
            const p = result.ping;
            parts.push(`<div class="diag-detail-row">
                <span class="diag-detail-label">Ping</span>
                <span class="diag-detail-value" style="color: ${p.alive ? 'var(--success)' : 'var(--error)'}">
                    ${p.alive
                        ? (p.rtt_avg !== null ? p.rtt_avg.toFixed(1) + ' ms' : 'OK')
                        : 'Недоступен'
                    }${p.packet_loss > 0 && p.packet_loss < 100 ? ` (потери: ${p.packet_loss}%)` : ''}
                </span>
            </div>`);
        }

        // DNS
        if (result.dns && result.dns.length > 0) {
            const allOk = result.dns.every(d => d.ok);
            const ips = result.dns.filter(d => d.ok).flatMap(d => d.resolved_ips).slice(0, 4);
            parts.push(`<div class="diag-detail-row">
                <span class="diag-detail-label">DNS</span>
                <span class="diag-detail-value" style="color: ${allOk ? 'var(--success)' : 'var(--warning)'}">
                    ${allOk ? 'OK' : 'Частично'}
                    ${ips.length ? '<span class="diag-detail-ips">' + ips.map(ip => _esc(ip)).join(', ') + '</span>' : ''}
                </span>
            </div>`);
        }

        // HTTP
        if (result.http && result.http.length > 0) {
            result.http.forEach(h => {
                parts.push(`<div class="diag-detail-row">
                    <span class="diag-detail-label">HTTP</span>
                    <span class="diag-detail-value" style="color: ${h.ok ? 'var(--success)' : 'var(--error)'}">
                        ${h.ok ? h.status_code : 'Ошибка'}
                        ${h.response_time !== null ? ` · ${h.response_time} ms` : ''}
                        ${h.tls_version ? ` · ${h.tls_version}` : ''}
                        ${h.error ? ` · <span class="diag-detail-error">${_esc(h.error.substring(0,60))}</span>` : ''}
                    </span>
                </div>`);
            });
        }

        return parts.join('');
    }

    /* ═══════════════════ Render: Система ═══════════════════ */

    function renderSystemInfo() {
        const el = document.getElementById('diag-system-info');
        if (!el || !systemInfo) return;

        const si = systemInfo;
        const ram = si.ram || {};

        let interfacesHtml = '';
        if (si.network_interfaces && si.network_interfaces.length > 0) {
            interfacesHtml = si.network_interfaces.map(iface =>
                `<span class="diag-iface-badge">${_esc(iface.name)}: ${_esc(iface.address)}/${iface.prefix}</span>`
            ).join(' ');
        }

        el.innerHTML = `
            <div class="diag-info-grid">
                <div class="diag-info-item">
                    <span class="diag-info-label">Хост</span>
                    <span class="diag-info-value">${_esc(si.hostname || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Платформа</span>
                    <span class="diag-info-value">${_esc(si.platform || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Ядро</span>
                    <span class="diag-info-value">${_esc(si.kernel || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Архитектура</span>
                    <span class="diag-info-value">${_esc(si.arch || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Uptime</span>
                    <span class="diag-info-value">${_esc(si.uptime_human || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">RAM</span>
                    <span class="diag-info-value">
                        ${ram.total_mb ? ram.total_mb + ' MB' : '—'}
                        ${ram.used_percent ? ' <span class="diag-ram-bar"><span class="diag-ram-fill" style="width:' + ram.used_percent + '%;background:' + (ram.used_percent > 80 ? 'var(--error)' : ram.used_percent > 60 ? 'var(--warning)' : 'var(--success)') + '"></span></span> ' + ram.used_percent + '%' : ''}
                    </span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Load Average</span>
                    <span class="diag-info-value">${_esc(si.load_avg || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">WAN IP</span>
                    <span class="diag-info-value">${_esc(si.wan_ip || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Default Gateway</span>
                    <span class="diag-info-value">${_esc(si.default_gateway || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">DNS серверы</span>
                    <span class="diag-info-value">${si.dns_servers && si.dns_servers.length ? si.dns_servers.map(d => _esc(d)).join(', ') : '—'}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Python</span>
                    <span class="diag-info-value">${_esc(si.python_version || '—')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Entware</span>
                    <span class="diag-info-value">${si.entware_installed ? '<span style="color:var(--success)">Установлен</span>' : '<span style="color:var(--text-muted)">Нет</span>'}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">nfqws2</span>
                    <span class="diag-info-value">
                        ${si.nfqws_binary_exists
                            ? '<span style="color:var(--success)">Найден</span>' + (si.nfqws_version ? ' · v' + _esc(si.nfqws_version) : '')
                            : '<span style="color:var(--error)">Не найден</span>'
                        }
                    </span>
                </div>
            </div>
            ${interfacesHtml ? `
                <div class="diag-interfaces-section">
                    <div class="diag-info-label" style="margin-bottom:6px">Сетевые интерфейсы</div>
                    <div class="diag-iface-list">${interfacesHtml}</div>
                </div>
            ` : ''}
        `;
    }

    /* ═══════════════════ Render: Firewall ═══════════════════ */

    function renderFirewall() {
        const el = document.getElementById('diag-firewall');
        if (!el || !firewallInfo) return;

        const fi = firewallInfo;
        const rulesCount = fi.rules ? fi.rules.length : 0;

        let rulesHtml = '';
        if (rulesCount > 0) {
            rulesHtml = `
                <div class="diag-fw-rules">
                    ${fi.rules.map(r => `
                        <div class="diag-fw-rule">
                            <span class="blob-badge ${r.type === 'nfqueue' ? 'blob-badge-builtin' : 'blob-badge-user'}">${_esc(r.type)}</span>
                            <code class="diag-fw-rule-text">${_esc(r.rule)}</code>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        el.innerHTML = `
            <div class="diag-info-grid">
                <div class="diag-info-item">
                    <span class="diag-info-label">Тип</span>
                    <span class="diag-info-value">${_esc(fi.type || 'Не определён')}</span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">NFQUEUE</span>
                    <span class="diag-info-value" style="color:${fi.nfqueue_available ? 'var(--success)' : 'var(--error)'}">
                        ${fi.nfqueue_available ? 'Доступен' : 'Недоступен'}
                    </span>
                </div>
                <div class="diag-info-item">
                    <span class="diag-info-label">Правила zapret</span>
                    <span class="diag-info-value">${rulesCount > 0
                        ? '<span style="color:var(--success)">' + rulesCount + ' правил(о)</span>'
                        : '<span style="color:var(--text-muted)">Нет</span>'
                    }</span>
                </div>
            </div>
            ${rulesHtml}
        `;
    }

    /* ═══════════════════ Render: Конфликты ═══════════════════ */

    function renderConflicts() {
        const el = document.getElementById('diag-conflicts');
        if (!el || !conflictsInfo) return;

        const ci = conflictsInfo;

        if (!ci.has_conflicts) {
            el.innerHTML = `
                <div class="diag-no-conflicts">
                    <span class="diag-dot diag-dot-ok"></span>
                    Конфликтов не обнаружено — нет сторонних процессов nfqws/tpws.
                </div>
            `;
            return;
        }

        el.innerHTML = `
            <div class="diag-conflicts-warning">
                <svg viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2" width="18" height="18">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                Обнаружены сторонние процессы, которые могут конфликтовать:
            </div>
            <div class="diag-conflicts-list">
                ${ci.conflicts.map(c => `
                    <div class="diag-conflict-item">
                        <span class="diag-conflict-pid">PID ${c.pid}</span>
                        <span class="diag-conflict-name">${_esc(c.name)}</span>
                        <code class="diag-conflict-cmd">${_esc(c.cmdline)}</code>
                    </div>
                `).join('')}
            </div>
        `;
    }

    /* ═══════════════════ Actions ═══════════════════ */

    async function checkService(name) {
        if (checking[name]) return;
        checking[name] = true;
        renderServicesGrid();

        try {
            const data = await API.post('/api/diagnostics/service', { name });
            if (data.ok) {
                serviceResults[name] = data.result;
            }
        } catch (e) {
            serviceResults[name] = { name, status: 'down', error: 'Ошибка запроса' };
        } finally {
            checking[name] = false;
            renderServicesGrid();
        }
    }

    async function checkAll() {
        if (checkAllRunning) return;
        checkAllRunning = true;

        const btn = document.getElementById('diag-check-all');
        if (btn) { btn.disabled = true; btn.textContent = 'Проверка…'; }

        const progress = document.getElementById('diag-progress');
        const progressBar = document.getElementById('diag-progress-bar');
        const progressText = document.getElementById('diag-progress-text');
        if (progress) progress.classList.remove('hidden');

        const names = Object.keys(services);
        const total = names.length;
        let done = 0;

        // Проверяем каждый сервис последовательно, обновляя карточки
        for (const name of names) {
            checking[name] = true;
            renderServicesGrid();

            if (progressText) progressText.textContent = `Проверка ${services[name].name}… (${done + 1}/${total})`;
            if (progressBar) progressBar.style.width = `${(done / total) * 100}%`;

            try {
                const data = await API.post('/api/diagnostics/service', { name });
                if (data.ok) {
                    serviceResults[name] = data.result;
                }
            } catch (e) {
                serviceResults[name] = { name, status: 'down', error: 'Ошибка запроса' };
            }

            checking[name] = false;
            done++;
            if (progressBar) progressBar.style.width = `${(done / total) * 100}%`;
            renderServicesGrid();
        }

        if (progressText) progressText.textContent = 'Готово!';
        checkAllRunning = false;

        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `
                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                </svg>
                Проверить все
            `;
        }

        // Скрываем прогресс через 2 сек
        setTimeout(() => {
            if (progress) progress.classList.add('hidden');
        }, 2000);

        // Подсчитываем итоги
        const ok = Object.values(serviceResults).filter(r => r.status === 'ok').length;
        const down = Object.values(serviceResults).filter(r => r.status === 'down').length;
        if (typeof Toast !== 'undefined') {
            Toast.show(
                `Проверка завершена: ${ok} доступно, ${down} недоступно`,
                down > 0 ? 'warning' : 'success'
            );
        }
    }

    async function refreshSystem() {
        // Перезагружаем все системные данные
        document.getElementById('diag-system-info').innerHTML = '<div class="diag-loading">Обновление…</div>';
        document.getElementById('diag-firewall').innerHTML = '<div class="diag-loading">Обновление…</div>';
        document.getElementById('diag-conflicts').innerHTML = '<div class="diag-loading">Обновление…</div>';
        await Promise.all([loadSystemInfo(), loadFirewall(), loadConflicts()]);
        if (typeof Toast !== 'undefined') Toast.show('Системная информация обновлена', 'success');
    }

    /* ═══════════════════ Ручные проверки ═══════════════════ */

    async function manualPing() {
        const host = (document.getElementById('diag-ping-host')?.value || '').trim();
        if (!host) return;
        const out = document.getElementById('diag-manual-output');
        if (out) out.textContent = `Ping ${host}…`;

        try {
            const data = await API.post('/api/diagnostics/ping', { host });
            if (data.ok) {
                const r = data.result;
                if (out) out.textContent =
                    `Ping ${r.host}: ${r.alive ? 'OK' : 'FAIL'}\n` +
                    `Packet loss: ${r.packet_loss}%\n` +
                    (r.rtt_avg !== null ? `RTT: ${r.rtt_min}/${r.rtt_avg}/${r.rtt_max} ms\n` : '') +
                    `\n--- Raw ---\n${r.raw_output}`;
            } else {
                if (out) out.textContent = `Ошибка: ${data.error}`;
            }
        } catch (e) {
            if (out) out.textContent = `Ошибка запроса: ${e.message}`;
        }
    }

    async function manualHttp() {
        const url = (document.getElementById('diag-http-url')?.value || '').trim();
        if (!url) return;
        const out = document.getElementById('diag-manual-output');
        if (out) out.textContent = `HTTP проверка ${url}…`;

        try {
            const data = await API.post('/api/diagnostics/http', { url });
            if (data.ok) {
                const r = data.result;
                if (out) out.textContent =
                    `URL: ${r.url}\n` +
                    `Статус: ${r.ok ? 'OK' : 'FAIL'} (${r.status_code})\n` +
                    `Время ответа: ${r.response_time !== null ? r.response_time + ' ms' : '—'}\n` +
                    (r.tls_version ? `TLS: ${r.tls_version}\n` : '') +
                    (r.redirect_url ? `Redirect: ${r.redirect_url}\n` : '') +
                    (r.error ? `Ошибка: ${r.error}\n` : '');
            } else {
                if (out) out.textContent = `Ошибка: ${data.error}`;
            }
        } catch (e) {
            if (out) out.textContent = `Ошибка запроса: ${e.message}`;
        }
    }

    async function manualDns() {
        const domain = (document.getElementById('diag-dns-domain')?.value || '').trim();
        if (!domain) return;
        const out = document.getElementById('diag-manual-output');
        if (out) out.textContent = `DNS resolve ${domain}…`;

        try {
            const data = await API.post('/api/diagnostics/dns', { domain });
            if (data.ok) {
                const r = data.result;
                if (out) out.textContent =
                    `Домен: ${r.domain}\n` +
                    `DNS сервер: ${r.dns_server}\n` +
                    `Статус: ${r.ok ? 'OK' : 'FAIL'}\n` +
                    `Время: ${r.response_time !== null ? r.response_time + ' ms' : '—'}\n` +
                    (r.resolved_ips.length ? `IP-адреса:\n  ${r.resolved_ips.join('\n  ')}\n` : '') +
                    (r.error ? `Ошибка: ${r.error}\n` : '');
            } else {
                if (out) out.textContent = `Ошибка: ${data.error}`;
            }
        } catch (e) {
            if (out) out.textContent = `Ошибка запроса: ${e.message}`;
        }
    }

    /* ═══════════════════ utils ═══════════════════ */
    function _esc(str) {
        if (!str) return '';
        const d = document.createElement('div');
        d.textContent = String(str);
        return d.innerHTML;
    }

    /* ═══════════════════ public API ═══════════════════ */
    return {
        render,
        destroy,
        checkService,
        checkAll,
        refreshSystem,
        manualPing,
        manualHttp,
        manualDns,
    };
})();

