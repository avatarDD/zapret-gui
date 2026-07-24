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

                <div class="status-card" id="card-zapret-ver" data-action="hash-zapret">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                <polyline points="7 10 12 15 17 10"/>
                                <line x1="12" y1="15" x2="12" y2="3"/>
                            </svg>
                        </span>
                        <span class="status-card-label">zapret2</span>
                    </div>
                    <div class="status-card-value" id="zapret-ver-value" style="font-size: 14px;">—</div>
                    <div class="status-card-detail" id="zapret-ver-detail"></div>
                </div>
            </div>

            <!-- VPN / Туннели -->
            <h2 style="font-size:14px; color:var(--text-muted); margin:16px 0 8px; text-transform:uppercase; letter-spacing:0.5px;">VPN / Туннели</h2>
            <div class="status-grid" id="vpn-grid">
                <div class="status-card" id="card-warp" data-action="hash-usque">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                            </svg>
                        </span>
                        <span class="status-card-label">WARP/MASQUE</span>
                    </div>
                    <div class="status-card-value stopped" id="warp-status">—</div>
                    <div class="status-card-detail" id="warp-detail"></div>
                </div>

                <div class="status-card" id="card-opera" data-action="hash-opera-proxy">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Opera Proxy</span>
                    </div>
                    <div class="status-card-value stopped" id="opera-status">—</div>
                    <div class="status-card-detail" id="opera-detail"></div>
                </div>

                <div class="status-card" id="card-telegram" data-action="hash-tgproxy">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Telegram</span>
                    </div>
                    <div class="status-card-value stopped" id="tg-status">—</div>
                    <div class="status-card-detail" id="tg-detail"></div>
                </div>
            </div>

            <!-- Мониторинг -->
            <h2 style="font-size:14px; color:var(--text-muted); margin:16px 0 8px; text-transform:uppercase; letter-spacing:0.5px;">Мониторинг</h2>
            <div class="status-grid" id="monitoring-grid">
                <div class="status-card" id="card-block-detector" data-action="hash-block-detector">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Block Detector</span>
                    </div>
                    <div class="status-card-value stopped" id="bd-status">—</div>
                    <div class="status-card-detail" id="bd-detail"></div>
                </div>

                <div class="status-card" id="card-healthcheck" data-action="hash-strategies">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Healthcheck</span>
                    </div>
                    <div class="status-card-value stopped" id="hc-status">—</div>
                    <div class="status-card-detail" id="hc-detail"></div>
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
                    <button class="btn btn-ghost" id="dash-btn-start" data-action="quickStart">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="5 3 19 12 5 21 5 3"/>
                        </svg>
                        Запустить
                    </button>
                    <button class="btn btn-ghost" id="dash-btn-stop" data-action="quickStop" disabled>
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                        </svg>
                        Остановить
                    </button>
                    <button class="btn btn-ghost" id="dash-btn-restart" data-action="quickRestart" disabled>
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
        refreshDashboard();

        // Polling
        startPolling();
        bindEvents();
    }

    async function refreshDashboard() {
        try {
            const res = await API.get('/api/dashboard/status');
            if (res.ok) {
                lastData = res.status;
                if (res.status) updateCards(res.status);
                updateVpnCards(res.warp, res.opera, res.tgproxy);
                updateMonitoringCards(res.block_detector, res.healthcheck);
                renderLogs(res.logs || []);
            }
        } catch (err) {
            const statusEl = document.getElementById('nfqws-status');
            if (statusEl) {
                statusEl.textContent = 'Ошибка';
                statusEl.className = 'status-card-value stopped';
            }
            const detailEl = document.getElementById('nfqws-detail');
            if (detailEl) {
                detailEl.textContent = err.message;
            }
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
            status.textContent = running ? _t('status_running') : _t('status_stopped');
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
            ['dash-btn-start', 'dash-btn-stop', 'dash-btn-restart'].forEach(id => {
                const b = document.getElementById(id);
                if (!b) return;
                if (id === 'dash-btn-start') b.disabled = running;
                else b.disabled = !running;
            });
        }

        // Стратегия
        const stName = document.getElementById('strategy-name');
        const stDetail = document.getElementById('strategy-detail');
        if (stName) stName.textContent = data.strategy?.name || 'Не выбрана';
        if (stDetail) {
            stDetail.textContent = data.strategy?.id ? `ID: ${data.strategy.id}` : '';
        }

        // Автозапуск
        const asVal = document.getElementById('autostart-status');
        const asDetail = document.getElementById('autostart-detail');
        if (asVal) {
            const asOk = data.autostart?.enabled;
            asVal.textContent = asOk ? 'Включен' : 'Выключен';
            asVal.className = `status-card-value ${asOk ? 'running' : 'stopped'}`;
        }
        if (asDetail) {
            const hasHook = data.autostart?.script_installed;
            asDetail.textContent = hasHook ? 'Служба установлена' : 'Служба не активна';
        }

        // Система
        const sysVal = document.getElementById('system-info');
        const sysDetail = document.getElementById('system-detail');
        if (sysVal && data.system) {
            sysVal.textContent = data.system.platform || 'Linux';
            sysVal.style.fontSize = '16px';
        }
        if (sysDetail && data.system) {
            const model = data.system.model || '';
            const cpu = data.system.cpu_load !== undefined ? `CPU: ${data.system.cpu_load}%` : '';
            sysDetail.textContent = [model, cpu].filter(Boolean).join(' · ');
        }

        // zapret2 версия
        const zVal = document.getElementById('zapret-ver-value');
        const zDetail = document.getElementById('zapret-ver-detail');
        if (zVal) {
            zVal.textContent = data.zapret?.version || 'Не установлен';
        }
        if (zDetail) {
            zDetail.textContent = `GUI: ${data.gui_version || '—'}`;
        }
    }

    /** MR-131: Показать/скрыть карточку службы в зависимости от статуса */
    function _toggleCard(cardId, hasContent) {
        const card = document.getElementById(cardId);
        if (!card) return;
        if (hasContent) {
            card.classList.remove('hidden');
        } else {
            card.classList.add('hidden');
        }
    }

    function updateVpnCards(warp, opera, tg) {
        // warp
        const warpEl = document.getElementById('warp-status');
        const warpDetail = document.getElementById('warp-detail');
        const warpInstalled = Array.isArray(warp) && warp.length > 0;
        if (warpEl) {
            const active = warpInstalled && warp.some(c => c.active);
            warpEl.textContent = active ? _t('status_running') : _t('status_stopped');
            warpEl.className = `status-card-value ${active ? 'running' : 'stopped'}`;
            if (warpDetail) {
                if (active) {
                    const c = warp.find(c => c.active);
                    warpDetail.textContent = `${c.name || 'warp'} (${c.iface || '?'})`;
                } else {
                    warpDetail.textContent = '';
                }
            }
        }
        // MR-131: скрыть карточку WARP если не установлен
        _toggleCard('card-warp', warpInstalled);

        // opera
        const operaEl = document.getElementById('opera-status');
        const operaDetail = document.getElementById('opera-detail');
        const operaInstalled = opera && (opera.installed || opera.running !== undefined);
        if (operaEl) {
            const active = opera && opera.running;
            operaEl.textContent = active ? _t('status_running') : _t('status_stopped');
            operaEl.className = `status-card-value ${active ? 'running' : 'stopped'}`;
            if (operaDetail) {
                operaDetail.textContent = active ? `Port: ${opera.port || '18080'}` : '';
            }
        }
        // MR-131: скрыть если не установлен
        _toggleCard('card-opera', operaInstalled);

        // telegram
        const tgEl = document.getElementById('tg-status');
        const tgDetail = document.getElementById('tg-detail');
        const tgInstalled = tg && (tg.installed || tg.running !== undefined);
        if (tgEl) {
            const active = tg && tg.running;
            tgEl.textContent = active ? _t('status_running') : _t('status_stopped');
            tgEl.className = `status-card-value ${active ? 'running' : 'stopped'}`;
            if (tgDetail) {
                tgDetail.textContent = active ? `Engine: ${tg.engine || '?'}` : '';
            }
        }
        // MR-131: скрыть если не установлен
        _toggleCard('card-telegram', tgInstalled);
    }

    function updateMonitoringCards(bd, hc) {
        // block detector
        const bdEl = document.getElementById('bd-status');
        const bdDetail = document.getElementById('bd-detail');
        const bdInstalled = bd && (bd.running !== undefined || bd.monitored_count !== undefined);
        if (bdEl) {
            const active = bd && bd.running;
            bdEl.textContent = active ? 'Активен' : 'Выключен';
            bdEl.className = `status-card-value ${active ? 'running' : 'stopped'}`;
            if (bdDetail) {
                bdDetail.textContent = active ? `Под наблюдением: ${bd.monitored_count || 0}` : '';
            }
        }
        // MR-131: скрыть если не установлен
        _toggleCard('card-block-detector', bdInstalled);

        // healthcheck
        const hcEl = document.getElementById('hc-status');
        const hcDetail = document.getElementById('hc-detail');
        const hcInstalled = hc && (hc.enabled !== undefined || hc.settings !== undefined);
        if (hcEl) {
            const active = hc && hc.enabled;
            if (active) {
                const running = hc.running;
                hcEl.textContent = running ? 'Активен' : 'В ожидании';
                hcEl.className = 'status-card-value running';
                if (hcDetail) {
                    const failStr = hc.consecutive_failures ? ` (Сбоев: ${hc.consecutive_failures})` : '';
                    hcDetail.textContent = `Интервал: ${hc.settings?.interval_min || 0}м${failStr}`;
                }
            } else {
                hcEl.textContent = 'Выключен';
                hcEl.className = 'status-card-value stopped';
                if (hcDetail) hcDetail.textContent = '';
            }
        }
        // MR-131: скрыть если не настроен
        _toggleCard('card-healthcheck', hcInstalled);
    }

    function renderLogs(entries) {
        const el = document.getElementById('dashboard-logs');
        if (!el) return;

        if (entries.length === 0) {
            el.innerHTML = '<div class="text-muted" style="padding:16px; text-align:center;">Нет записей</div>';
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
                <span class="log-level" style="color:${e.color || '#9ca3af'}">${e.level || ''}</span>
                <span class="log-message">${msgHtml}</span>
            </div>
        `;}).join('');

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
            refreshDashboard();
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function startPolling() {
        stopPolling();
        if (!document.hidden) {
            pollTimer = setInterval(() => {
                refreshDashboard();
            }, 3000);
        }
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    function onVisibilityChange() {
        if (document.hidden) {
            stopPolling();
        } else {
            requestAnimationFrame(() => {
                refreshDashboard();
                startPolling();
            });
        }
    }

    // Именованный обработчик — чтобы снять его в destroy(). Dashboard вешает
    // делегацию на .content (родитель #page-container, который роутер НЕ
    // заменяет), поэтому без removeEventListener слушатели накапливались бы
    // на каждый заход на страницу.
    function onContentClick(e) {
        const el = e.target.closest('[data-action]');
        if (!el) return;
        const a = el.dataset.action;
        if (a === 'quickStart') { quickAction('start'); return; }
        if (a === 'quickStop') { quickAction('stop'); return; }
        if (a === 'quickRestart') { quickAction('restart'); return; }
        if (a === 'hash-zapret') { window.location.hash = 'zapret'; return; }
        if (a === 'hash-usque') { window.location.hash = 'usque'; return; }
        if (a === 'hash-opera-proxy') { window.location.hash = 'opera-proxy'; return; }
        if (a === 'hash-tgproxy') { window.location.hash = 'tgproxy'; return; }
        if (a === 'hash-block-detector') { window.location.hash = 'block-detector'; return; }
        if (a === 'hash-strategies') { window.location.hash = 'strategies'; return; }
    }

    function bindEvents() {
        document.addEventListener('visibilitychange', onVisibilityChange);
        // MR-69: Event delegation вместо inline onclick
        document.querySelector('.content')?.addEventListener('click', onContentClick);
    }

    function destroy() {
        stopPolling();
        document.removeEventListener('visibilitychange', onVisibilityChange);
        document.querySelector('.content')?.removeEventListener('click', onContentClick);
    }

    return {
        render,
        destroy,
        quickStart:   () => quickAction('start'),
        quickStop:    () => quickAction('stop'),
        quickRestart: () => quickAction('restart'),
    };
})();
