/**
 * control.js — Страница "Управление".
 *
 * Большой индикатор статуса, кнопки управления,
 * текущая стратегия, статус firewall, лог nfqws.
 */

const ControlPage = (() => {
    let pollTimer = null;
    let isActionPending = false;

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Управление</h1>
                <p class="page-description">Запуск, остановка и мониторинг nfqws2</p>
            </div>

            <!-- Большой индикатор статуса -->
            <div class="control-status-hero" id="control-hero">
                <div class="control-status-indicator stopped" id="control-indicator">
                    <div class="control-status-ring"></div>
                    <div class="control-status-icon" id="control-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="32" height="32">
                            <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                        </svg>
                    </div>
                </div>
                <div class="control-status-text">
                    <div class="control-status-label" id="control-status-label">Остановлен</div>
                    <div class="control-status-detail" id="control-status-detail">nfqws2 не запущен</div>
                </div>
            </div>

            <!-- Кнопки управления -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                    </svg>
                    Управление процессом
                </div>
                <div class="control-buttons" id="control-buttons">
                    <button class="btn btn-success btn-lg" id="btn-start" onclick="ControlPage.doStart()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="5 3 19 12 5 21 5 3"/>
                        </svg>
                        Запустить
                    </button>
                    <button class="btn btn-danger btn-lg" id="btn-stop" onclick="ControlPage.doStop()" disabled>
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                        </svg>
                        Остановить
                    </button>
                    <button class="btn btn-primary btn-lg" id="btn-restart" onclick="ControlPage.doRestart()" disabled>
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                        Перезапустить
                    </button>
                </div>
            </div>

            <!-- Информационные карточки -->
            <div class="status-grid">
                <!-- Стратегия -->
                <div class="status-card" style="cursor:pointer;" onclick="window.location.hash='strategies';" title="Перейти к стратегиям">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Стратегия</span>
                    </div>
                    <div class="status-card-value" id="ctrl-strategy-name">—</div>
                    <div class="status-card-detail" id="ctrl-strategy-detail">
                        <a href="#strategies" style="color:var(--accent); font-size:12px;">Выбрать стратегию →</a>
                    </div>
                </div>

                <!-- PID / Uptime -->
                <div class="status-card">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Процесс</span>
                    </div>
                    <div class="status-card-value" id="ctrl-process-info">—</div>
                    <div class="status-card-detail" id="ctrl-process-detail"></div>
                </div>

                <!-- Firewall -->
                <div class="status-card">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Firewall</span>
                    </div>
                    <div class="status-card-value" id="ctrl-fw-status">—</div>
                    <div class="status-card-detail" id="ctrl-fw-detail"></div>
                </div>
            </div>

            <!-- Firewall правила -->
            <div class="card" id="fw-rules-card" style="display:none;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Правила Firewall
                </div>
                <div class="log-viewer" id="fw-rules-viewer" style="max-height:160px; font-size:11px;">
                </div>
            </div>

            <!-- Лог вывода nfqws -->
            <div class="card">
                <div class="card-title" style="justify-content: space-between;">
                    <span style="display:flex;align-items:center;gap:8px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                        Вывод nfqws2
                    </span>
                    <a href="#logs" class="text-muted" style="font-size:12px;">Все логи →</a>
                </div>
                <div class="log-viewer" id="control-logs" style="max-height: 240px;">
                    <div class="text-muted" style="padding:16px; text-align:center;">
                        Загрузка...
                    </div>
                </div>
            </div>
        `;

        // Начальная загрузка
        fetchStatus();
        fetchLogs();
        startPolling();
    }

    // ── Status fetching ──

    async function fetchStatus() {
        try {
            const data = await API.get('/api/status');
            updateUI(data);
        } catch (err) {
            updateUIError(err.message);
        }
    }

    function updateUI(data) {
        const running = data.nfqws?.running;
        const indicator = document.getElementById('control-indicator');
        const icon = document.getElementById('control-icon');
        const label = document.getElementById('control-status-label');
        const detail = document.getElementById('control-status-detail');

        // Hero indicator
        if (indicator) {
            indicator.className = 'control-status-indicator ' + (running ? 'running' : 'stopped');
        }
        if (icon) {
            icon.innerHTML = running
                ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="32" height="32"><polygon points="5 3 19 12 5 21 5 3"/></svg>'
                : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="32" height="32"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>';
        }
        if (label) {
            label.textContent = running ? 'Работает' : 'Остановлен';
            label.className = 'control-status-label ' + (running ? 'text-success' : 'text-error');
        }
        if (detail) {
            if (running) {
                const parts = [];
                if (data.nfqws.pid) parts.push('PID ' + data.nfqws.pid);
                if (data.nfqws.uptime_human) parts.push('uptime ' + data.nfqws.uptime_human);
                detail.textContent = parts.join(' · ');
            } else {
                const ec = data.nfqws?.exit_code;
                detail.textContent = ec !== null && ec !== undefined
                    ? 'Последний exit code: ' + ec
                    : 'nfqws2 не запущен';
            }
        }

        // Кнопки
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const btnRestart = document.getElementById('btn-restart');
        if (!isActionPending) {
            if (btnStart) btnStart.disabled = running;
            if (btnStop) btnStop.disabled = !running;
            if (btnRestart) btnRestart.disabled = !running;
        }

        // Стратегия
        const stratName = document.getElementById('ctrl-strategy-name');
        const stratDetail = document.getElementById('ctrl-strategy-detail');
        if (stratName) {
            const name = data.strategy?.name;
            stratName.textContent = name || 'Не выбрана';
        }
        if (stratDetail) {
            if (data.strategy?.id) {
                stratDetail.innerHTML = '<a href="#strategies" style="color:var(--accent); font-size:12px;">Изменить стратегию →</a>';
            } else {
                stratDetail.innerHTML = '<a href="#strategies" style="color:var(--accent); font-size:12px;">Выбрать стратегию →</a>';
            }
        }

        // Процесс
        const procInfo = document.getElementById('ctrl-process-info');
        const procDetail = document.getElementById('ctrl-process-detail');
        if (procInfo) {
            procInfo.textContent = running ? ('PID ' + data.nfqws.pid) : 'Не запущен';
            procInfo.className = 'status-card-value ' + (running ? 'running' : 'stopped');
        }
        if (procDetail) {
            procDetail.textContent = running && data.nfqws.uptime_human
                ? 'Uptime: ' + data.nfqws.uptime_human
                : '';
        }

        // Firewall
        const fwStatus = document.getElementById('ctrl-fw-status');
        const fwDetail = document.getElementById('ctrl-fw-detail');
        const fwApplied = data.firewall?.applied;
        if (fwStatus) {
            fwStatus.textContent = fwApplied ? 'Активен' : 'Не активен';
            fwStatus.className = 'status-card-value ' + (fwApplied ? 'running' : '');
        }
        if (fwDetail) {
            const parts = [];
            if (data.firewall?.type) parts.push(data.firewall.type);
            if (data.firewall?.rules_count) parts.push(data.firewall.rules_count + ' правил');
            fwDetail.textContent = parts.join(' · ');
        }

        // Firewall rules card
        const fwCard = document.getElementById('fw-rules-card');
        const fwViewer = document.getElementById('fw-rules-viewer');
        if (fwCard && fwViewer && data.firewall?.rules?.length > 0) {
            fwCard.style.display = '';
            fwViewer.innerHTML = data.firewall.rules
                .map(r => '<div class="log-entry"><span class="log-message" style="color:var(--text-secondary)">' + escapeHtml(r) + '</span></div>')
                .join('');
        } else if (fwCard) {
            fwCard.style.display = 'none';
        }
    }

    function updateUIError(msg) {
        const label = document.getElementById('control-status-label');
        if (label) {
            label.textContent = 'Ошибка';
            label.className = 'control-status-label text-error';
        }
        const detail = document.getElementById('control-status-detail');
        if (detail) detail.textContent = msg;
    }

    // ── Logs ──

    async function fetchLogs() {
        try {
            const data = await API.get('/api/logs?n=30&level=DEBUG');
            const entries = (data.entries || []).filter(
                e => e.source === 'nfqws' || e.source === 'firewall' || e.source === 'control' || e.source === 'strategies'
            );
            renderLogs(entries.length > 0 ? entries : (data.entries || []).slice(-20));
        } catch {
            // тихо
        }
    }

    function renderLogs(entries) {
        const el = document.getElementById('control-logs');
        if (!el) return;
        if (entries.length === 0) {
            el.innerHTML = '<div class="text-muted" style="padding:16px;text-align:center;">Нет записей</div>';
            return;
        }
        el.innerHTML = entries.map(e => {
            const rawMsg = e.message || '';
            const msgHtml = NfqwsSyntax.hasNfqwsArgs(rawMsg)
                ? NfqwsSyntax.highlight(rawMsg)
                : escapeHtml(rawMsg);
            return `
            <div class="log-entry">
                <span class="log-time">${e.time || ''}</span>
                <span class="log-level" style="color:${e.color || '#9ca3af'}">${(e.level || '').padEnd(7)}</span>
                <span class="log-message">${msgHtml}</span>
            </div>
        `;}).join('');
        el.scrollTop = el.scrollHeight;
    }

    // ── Actions ──

    async function doStart() {
        if (isActionPending) return;
        setActionPending(true, 'start');
        try {
            const result = await API.post('/api/start', {});
            if (result.ok) {
                Toast.success('nfqws2 запущен');
            } else {
                Toast.error(result.error || 'Ошибка запуска');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            setActionPending(false);
            fetchStatus();
            fetchLogs();
        }
    }

    async function doStop() {
        if (isActionPending) return;
        setActionPending(true, 'stop');
        try {
            const result = await API.post('/api/stop', {});
            if (result.ok) {
                Toast.success('nfqws2 остановлен');
            } else {
                Toast.error(result.error || 'Ошибка остановки');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            setActionPending(false);
            fetchStatus();
            fetchLogs();
        }
    }

    async function doRestart() {
        if (isActionPending) return;
        setActionPending(true, 'restart');
        try {
            const result = await API.post('/api/restart', {});
            if (result.ok) {
                Toast.success('nfqws2 перезапущен');
            } else {
                Toast.error(result.error || 'Ошибка перезапуска');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            setActionPending(false);
            fetchStatus();
            fetchLogs();
        }
    }

    function setActionPending(pending, action) {
        isActionPending = pending;
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const btnRestart = document.getElementById('btn-restart');

        if (pending) {
            if (btnStart) btnStart.disabled = true;
            if (btnStop) btnStop.disabled = true;
            if (btnRestart) btnRestart.disabled = true;

            // Показываем спиннер в активной кнопке
            const activeBtn = {start: btnStart, stop: btnStop, restart: btnRestart}[action];
            if (activeBtn) {
                activeBtn._origHtml = activeBtn.innerHTML;
                activeBtn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px;"></span> Подождите...';
            }
        } else {
            // Восстанавливаем текст кнопок
            [btnStart, btnStop, btnRestart].forEach(btn => {
                if (btn && btn._origHtml) {
                    btn.innerHTML = btn._origHtml;
                    delete btn._origHtml;
                }
            });
        }
    }

    // ── Polling ──

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            fetchStatus();
            fetchLogs();
        }, 3000);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // ── Utils ──

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function destroy() {
        stopPolling();
    }

    return { render, destroy, doStart, doStop, doRestart };
})();



