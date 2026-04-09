/**
 * scan.js — Страница подбора стратегий (Strategy Scanner).
 *
 * Выбор цели, протокола, режима. Прогресс сканирования.
 * Список найденных стратегий с кнопкой «Применить».
 * Resume при прерывании.
 */

const ScanPage = (() => {
    /* ───────── state ───────── */
    let pollTimer = null;
    let lastStatus = null;

    /* ───────── lifecycle ───────── */

    function render(container) {
        container.innerHTML = `
            <div class="page-container">
                <div class="page-header">
                    <h1 class="page-title">Подбор стратегий</h1>
                    <p class="page-description">Автоматический поиск работающих стратегий обхода DPI</p>
                </div>

                <!-- Параметры -->
                <div class="card" id="scan-controls">
                    <div class="card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                        Параметры сканирования
                    </div>

                    <div class="bc-form">
                        <div class="bc-form-row">
                            <div class="form-group" style="flex:2; min-width:200px;">
                                <label class="form-label">Целевой домен</label>
                                <input class="form-input" id="scan-target" type="text"
                                       placeholder="youtube.com" value="youtube.com"
                                       spellcheck="false" style="font-family:var(--font-mono); font-size:13px;">
                            </div>
                            <div class="form-group" style="flex:1; min-width:120px;">
                                <label class="form-label">Протокол</label>
                                <select class="form-select" id="scan-protocol">
                                    <option value="tcp" selected>TCP</option>
                                    <option value="udp">UDP</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1; min-width:140px;">
                                <label class="form-label">Режим</label>
                                <select class="form-select" id="scan-mode">
                                    <option value="quick" selected>Быстрый (~30)</option>
                                    <option value="standard">Стандарт (~80)</option>
                                    <option value="full">Полный (все)</option>
                                </select>
                            </div>
                        </div>

                        <div class="bc-actions" id="scan-actions">
                            <button class="btn btn-primary" id="scan-btn-start" onclick="ScanPage.start(false)">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polygon points="5 3 19 12 5 21 5 3"/>
                                </svg>
                                Запустить
                            </button>
                            <button class="btn btn-ghost btn-sm hidden" id="scan-btn-resume" onclick="ScanPage.start(true)">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                                </svg>
                                Продолжить
                            </button>
                            <button class="btn btn-ghost btn-sm hidden" id="scan-btn-stop" onclick="ScanPage.stop()" style="color:var(--error);">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="6" y="6" width="12" height="12" rx="1"/>
                                </svg>
                                Остановить
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Прогресс -->
                <div class="card hidden" id="scan-progress-card">
                    <div class="card-title">Прогресс</div>
                    <div class="bc-progress-info">
                        <span class="bc-phase" id="scan-phase"></span>
                        <span class="bc-elapsed" id="scan-elapsed"></span>
                    </div>
                    <div class="diag-progress" style="margin-top:8px;">
                        <div class="diag-progress-track">
                            <div class="diag-progress-bar" id="scan-progress-bar" style="width:0%"></div>
                        </div>
                        <span class="diag-progress-text" id="scan-progress-text">0 / 0</span>
                    </div>
                    <div id="scan-current-strategy" style="margin-top:8px; font-size:12px; color:var(--text-secondary); font-family:var(--font-mono); word-break:break-all;"></div>
                    <div style="display:flex; gap:16px; margin-top:8px; font-size:12px;">
                        <span style="color:var(--success);" id="scan-working-count">Найдено: 0</span>
                        <span style="color:var(--text-muted);" id="scan-failed-count">Не подошло: 0</span>
                        <span style="color:var(--accent);" id="scan-success-rate"></span>
                        <span style="color:var(--text-muted);" id="scan-elapsed-time"></span>
                    </div>
                </div>

                <!-- Результаты -->
                <div class="hidden" id="scan-results-section">
                    <div class="card">
                        <div class="card-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            Найденные стратегии
                        </div>
                        <div id="scan-results-summary" style="margin-bottom:12px; font-size:13px; color:var(--text-secondary);"></div>
                        <div id="scan-results-list"></div>
                    </div>
                </div>
            </div>
        `;

        fetchStatus();
    }

    function destroy() {
        stopPolling();
        lastStatus = null;
    }

    /* ───────── API ───────── */

    async function start(resume) {
        const target = (document.getElementById('scan-target')?.value || '').trim();
        if (!target) {
            Toast.error('Укажите целевой домен');
            return;
        }

        const body = {
            target,
            protocol: document.getElementById('scan-protocol')?.value || 'tcp',
            mode: document.getElementById('scan-mode')?.value || 'quick',
        };
        if (resume) body.resume = true;

        try {
            const res = await API.post('/api/scan/start', body);
            if (res.ok) {
                Toast.success(resume ? 'Сканирование продолжено' : 'Сканирование запущено');
                startPolling();
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function stop() {
        try {
            await API.post('/api/scan/stop', {});
            Toast.info('Остановка запрошена');
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function applyStrategy(idx) {
        try {
            const res = await API.post('/api/scan/apply/' + idx, {});
            if (res.ok) {
                Toast.success(res.message || 'Стратегия применена');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function fetchStatus() {
        try {
            const data = await API.get('/api/scan/status');
            lastStatus = data;
            updateUI(data);

            if (data.status === 'running') {
                startPolling();
            } else {
                stopPolling();
                // FIX: было 'stopped' — бэкенд отправляет 'cancelled'
                if (data.status === 'completed' || data.status === 'cancelled' || data.status === 'error') {
                    await fetchResults();
                }
            }
        } catch {
            // тихо
        }
    }

    async function fetchResults() {
        try {
            const data = await API.get('/api/scan/results');
            if (data.ok) {
                renderResults(data.working || [], data.report || null);
            }
        } catch {
            // тихо
        }
    }

    /* ───────── Polling ───────── */

    function startPolling() {
        if (pollTimer) return;
        pollTimer = setInterval(fetchStatus, 2000);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    /* ───────── UI update ───────── */

    function updateUI(data) {
        const isRunning = data.status === 'running';
        const isIdle = data.status === 'idle';
        // FIX: было 'stopped' — бэкенд отправляет 'cancelled'
        const isCancelled = data.status === 'cancelled';

        // Кнопки
        const btnStart = document.getElementById('scan-btn-start');
        const btnStop = document.getElementById('scan-btn-stop');
        const btnResume = document.getElementById('scan-btn-resume');
        if (btnStart) {
            btnStart.disabled = isRunning;
            btnStart.classList.toggle('btn-disabled', isRunning);
        }
        if (btnStop) btnStop.classList.toggle('hidden', !isRunning);
        if (btnResume) btnResume.classList.toggle('hidden', !isCancelled);

        // Inputs: заблокировать при запуске
        ['scan-target', 'scan-protocol', 'scan-mode'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = isRunning;
        });

        // Заполнить из статуса если есть данные
        if (data.target) {
            const el = document.getElementById('scan-target');
            if (el && !isRunning) el.value = data.target;
        }

        // Прогресс
        const progressCard = document.getElementById('scan-progress-card');
        if (progressCard) progressCard.classList.toggle('hidden', isIdle);

        if (!isIdle) {
            const pct = data.total > 0 ? Math.round((data.progress / data.total) * 100) : 0;

            setEl('scan-progress-bar', 'style.width', pct + '%');
            setElText('scan-progress-text', data.progress + ' / ' + data.total);
            setElText('scan-phase', data.phase || '');
            setElText('scan-current-strategy', data.current_strategy || '');
            setElText('scan-working-count', 'Найдено: ' + (data.working_count || 0));
            setElText('scan-failed-count', 'Не подошло: ' + (data.failed_count || 0));

            // Процент успешности
            const rate = data.success_rate;
            if (rate !== undefined && (data.working_count > 0 || data.failed_count > 0)) {
                setElText('scan-success-rate', 'Успешность: ' + rate + '%');
            } else {
                setElText('scan-success-rate', '');
            }

            // Время
            const elapsed = data.elapsed_seconds;
            if (elapsed > 0) {
                setElText('scan-elapsed-time', formatElapsed(elapsed));
            }
        }

        if (data.status === 'error') {
            setElText('scan-phase', 'Ошибка: ' + (data.error || 'неизвестная'));
        }
        if (data.status === 'completed') {
            setElText('scan-phase', 'Завершено');
            const bar = document.getElementById('scan-progress-bar');
            if (bar) { bar.style.width = '100%'; bar.style.background = 'var(--success)'; }
        }
        // FIX: было 'stopped' — бэкенд отправляет 'cancelled'
        if (data.status === 'cancelled') {
            setElText('scan-phase', 'Остановлено');
        }
    }

    /* ───────── Results ───────── */

    function renderResults(working, report) {
        const section = document.getElementById('scan-results-section');
        if (section) section.classList.remove('hidden');

        // Сводка
        const summaryEl = document.getElementById('scan-results-summary');
        if (summaryEl && report) {
            const elapsed = report.elapsed_seconds
                ? formatElapsed(report.elapsed_seconds)
                : '';
            const rate = report.success_rate !== undefined
                ? report.success_rate + '%'
                : '';
            const parts = [];
            parts.push('Протестировано: ' + (report.total_tested || 0) + '/' + (report.total_available || 0));
            parts.push('Рабочих: ' + (report.working_count || 0));
            if (rate) parts.push('Успешность: ' + rate);
            if (elapsed) parts.push('Время: ' + elapsed);
            if (report.best_strategy) {
                parts.push('Лучшая: ' + escapeHtml(report.best_strategy.strategy_name)
                    + ' (' + Math.round(report.best_strategy.latency_ms) + ' ms)');
            }
            summaryEl.innerHTML = parts.join(' · ');
        }

        const el = document.getElementById('scan-results-list');
        if (!el) return;

        if (working.length === 0) {
            el.innerHTML = `
                <div style="text-align:center; padding:24px; color:var(--text-muted);">
                    Работающие стратегии не найдены
                </div>
            `;
            return;
        }

        el.innerHTML = working.map((w, i) => {
            const latency = w.latency_ms ? Math.round(w.latency_ms) + ' ms' : '';
            const name = escapeHtml(w.strategy_name || w.strategy_id || 'Стратегия #' + (i + 1));
            // FIX: args_preview теперь приходит в raw_data
            const argsPreview = escapeHtml(
                (w.raw_data && w.raw_data.args_preview) || ''
            );
            const sourceFile = (w.raw_data && w.raw_data.source_file) || '';
            const level = (w.raw_data && w.raw_data.level) || '';
            const label = (w.raw_data && w.raw_data.label) || '';

            // Мета-информация
            const metaParts = [];
            if (level) metaParts.push(level);
            if (sourceFile) metaParts.push(sourceFile);
            if (label) metaParts.push(label);
            const metaStr = metaParts.length > 0
                ? '<span style="color:var(--text-muted); font-size:11px;">' + escapeHtml(metaParts.join(' · ')) + '</span>'
                : '';

            return `
                <div class="scan-result-item">
                    <div class="scan-result-header">
                        <div class="scan-result-name">
                            <span class="bc-badge bc-badge-ok">#${i + 1}</span>
                            ${name}
                            ${label === 'recommended' ? '<span class="bc-badge" style="background:rgba(34,197,94,0.15); color:var(--success); font-size:10px; padding:1px 6px;">recommended</span>' : ''}
                        </div>
                        <div class="scan-result-meta">
                            ${latency ? `<span style="color:var(--text-muted); font-size:12px;">${latency}</span>` : ''}
                            <button class="btn btn-primary btn-sm" onclick="ScanPage.applyStrategy(${i})">
                                Применить
                            </button>
                        </div>
                    </div>
                    ${metaStr ? '<div style="margin:4px 0 2px 28px;">' + metaStr + '</div>' : ''}
                    ${argsPreview ? `<div class="scan-result-args">${argsPreview}</div>` : ''}
                </div>
            `;
        }).join('');
    }

    /* ───────── helpers ───────── */

    function setElText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function setEl(id, prop, val) {
        const el = document.getElementById(id);
        if (!el) return;
        const parts = prop.split('.');
        let obj = el;
        for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
        obj[parts[parts.length - 1]] = val;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function formatElapsed(seconds) {
        if (!seconds || seconds <= 0) return '';
        if (seconds < 60) return Math.round(seconds) + ' сек';
        const m = Math.floor(seconds / 60);
        const s = Math.round(seconds % 60);
        return m + ' мин ' + s + ' сек';
    }

    /* ───────── public ───────── */

    return { render, destroy, start, stop, applyStrategy };
})();
