/**
 * dashboard.js — Главная страница (Dashboard).
 *
 * Показывает карточки статуса: nfqws, стратегия, автозапуск, система.
 * Polling каждые 3 секунды для обновления.
 * Кнопки быстрых действий управляют nfqws через API.
 */

const DashboardPage = (() => {
    let pollTimer = null;
    let lastData = null;
    let isActionPending = false;

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">Главная</h1>
                <p class="page-description">Обзор состояния системы</p>
            </div>

            <!-- Статус nfqws -->
            <div class="status-grid" id="status-grid">
                <div class="status-card" id="card-nfqws">
                    <div class="status-card-header">
                        <span class="status-dot stopped" id="nfqws-dot"></span>
                        <span class="status-card-label">nfqws2</span>
                    </div>
                    <div class="status-card-value stopped" id="nfqws-status">—</div>
                    <div class="status-card-detail" id="nfqws-detail"></div>
                </div>

                <div class="status-card" id="card-strategy">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Стратегия</span>
                    </div>
                    <div class="status-card-value" id="strategy-name">—</div>
                    <div class="status-card-detail" id="strategy-detail"></div>
                </div>

                <div class="status-card" id="card-autostart">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Автозапуск</span>
                    </div>
                    <div class="status-card-value" id="autostart-status">—</div>
                    <div class="status-card-detail" id="autostart-detail"></div>
                </div>

                <div class="status-card" id="card-system">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                <line x1="8" y1="21" x2="16" y2="21"/>
                                <line x1="12" y1="17" x2="12" y2="21"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Система</span>
                    </div>
                    <div class="status-card-value" id="system-info">—</div>
                    <div class="status-card-detail" id="system-detail"></div>
                </div>
            </div>

            <!-- Быстрые действия -->
            <div class="card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                         width="16" height="16">
                        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                    </svg>
                    Быстрые действия
                </div>
                <div class="actions-row" id="quick-actions">
                    <button class="btn btn-ghost" id="dash-btn-start" onclick="DashboardPage.quickStart()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="5 3 19 12 5 21 5 3"/>
                        </svg>
                        Запустить
                    </button>
                    <button class="btn btn-ghost" id="dash-btn-stop" onclick="DashboardPage.quickStop()" disabled>
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                        </svg>
                        Остановить
                    </button>
                    <button class="btn btn-ghost" id="dash-btn-restart" onclick="DashboardPage.quickRestart()" disabled>
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                        Перезапустить
                    </button>
                </div>
            </div>

            <!-- Последние логи -->
            <div class="card">
                <div class="card-title" style="justify-content: space-between;">
                    <span style="display:flex;align-items:center;gap:8px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                             width="16" height="16">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                        Последние события
                    </span>
                    <a href="#logs" class="text-muted" style="font-size:12px;">Все логи →</a>
                </div>
                <div class="log-viewer" id="dashboard-logs" style="max-height: 200px;">
                    <div class="text-muted" style="padding:16px; text-align:center;">
                        Загрузка логов...
                    </div>
                </div>
            </div>
        `;

        // Первая загрузка
        fetchStatus();
        fetchRecentLogs();

        // Polling
        startPolling();
    }

    async function fetchStatus() {
        try {
            const data = await API.get('/api/status');
            lastData = data;
            updateCards(data);
        } catch (err) {
            document.getElementById('nfqws-status').textContent = 'Ошибка';
            document.getElementById('nfqws-status').className = 'status-card-value stopped';
            document.getElementById('nfqws-detail').textContent = err.message;
        }
    }

    function updateCards(data) {
        // nfqws
        const running = data.nfqws?.running;
        const dot = document.getElementById('nfqws-dot');
        const status = document.getElementById('nfqws-status');
        const detail = document.getElementById('nfqws-detail');

        if (dot) {
            dot.className = `status-dot ${running ? 'running' : 'stopped'}`;
        }
        if (status) {
            status.textContent = running ? 'Работает' : 'Остановлен';
            status.className = `status-card-value ${running ? 'running' : 'stopped'}`;
        }
        if (detail) {
            if (running) {
                const parts = [];
                if (data.nfqws.pid) parts.push(`PID ${data.nfqws.pid}`);
                if (data.nfqws.uptime_human) parts.push(data.nfqws.uptime_human);
                detail.textContent = parts.join(' · ');
            } else {
                detail.textContent = '';
            }
        }

        // Кнопки быстрых действий
        if (!isActionPending) {
            const btnStart = document.getElementById('dash-btn-start');
            const btnStop = document.getElementById('dash-btn-stop');
            const btnRestart = document.getElementById('dash-btn-restart');
            if (btnStart) btnStart.disabled = running;
            if (btnStop) btnStop.disabled = !running;
            if (btnRestart) btnRestart.disabled = !running;
        }

        // Стратегия
        const stratName = document.getElementById('strategy-name');
        if (stratName) {
            stratName.textContent = data.strategy?.name || 'Не выбрана';
        }

        // Автозапуск
        const autoStatus = document.getElementById('autostart-status');
        if (autoStatus) {
            const enabled = data.autostart?.enabled;
            autoStatus.textContent = enabled ? 'Включён' : 'Выключен';
            autoStatus.className = `status-card-value ${enabled ? 'running' : ''}`;
        }

        // Система
        const sysInfo = document.getElementById('system-info');
        const sysDetail = document.getElementById('system-detail');
        if (sysInfo && data.system) {
            sysInfo.textContent = data.system.hostname || '—';
            const parts = [];
            if (data.system.platform) parts.push(data.system.platform);
            if (data.system.uptime_human) parts.push(`uptime ${data.system.uptime_human}`);
            if (data.system.ram?.used_percent) parts.push(`RAM ${data.system.ram.used_percent}%`);
            if (sysDetail) sysDetail.textContent = parts.join(' · ');
        }
    }

    async function fetchRecentLogs() {
        try {
            const data = await API.get('/api/logs?n=15');
            renderLogs(data.entries || []);
        } catch {
            // Тихо игнорируем
        }
    }

    function renderLogs(entries) {
        const el = document.getElementById('dashboard-logs');
        if (!el) return;

        if (entries.length === 0) {
            el.innerHTML = '<div class="text-muted" style="padding:16px; text-align:center;">Нет записей</div>';
            return;
        }

        el.innerHTML = entries.map(e => `
            <div class="log-entry">
                <span class="log-time">${e.time || ''}</span>
                <span class="log-level" style="color:${e.color || '#9ca3af'}">${e.level || ''}</span>
                <span class="log-message">${escapeHtml(e.message || '')}</span>
            </div>
        `).join('');

        // Scroll to bottom
        el.scrollTop = el.scrollHeight;
    }

    // ── Quick actions ──

    async function quickAction(action) {
        if (isActionPending) return;
        isActionPending = true;

        const btnMap = {start: 'dash-btn-start', stop: 'dash-btn-stop', restart: 'dash-btn-restart'};
        const btn = document.getElementById(btnMap[action]);

        // Disable all buttons, show spinner
        ['dash-btn-start', 'dash-btn-stop', 'dash-btn-restart'].forEach(id => {
            const b = document.getElementById(id);
            if (b) b.disabled = true;
        });
        let origHtml = '';
        if (btn) {
            origHtml = btn.innerHTML;
            btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;"></span>';
        }

        try {
            const result = await API.post('/api/' + action, {});
            if (result.ok) {
                const msgs = {start: 'nfqws2 запущен', stop: 'nfqws2 остановлен', restart: 'nfqws2 перезапущен'};
                Toast.success(msgs[action] || 'OK');
            } else {
                Toast.error(result.error || 'Ошибка');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            if (btn) btn.innerHTML = origHtml;
            isActionPending = false;
            fetchStatus();
            fetchRecentLogs();
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
            fetchStatus();
            fetchRecentLogs();
        }, 3000);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function destroy() {
        stopPolling();
    }

    return {
        render,
        destroy,
        quickStart:   () => quickAction('start'),
        quickStop:    () => quickAction('stop'),
        quickRestart: () => quickAction('restart'),
    };
})();

