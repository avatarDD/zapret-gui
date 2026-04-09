/**
 * blockcheck.js — Страница тестирования доступности (BlockCheck).
 *
 * Запуск тестирования (quick/full/dpi_only), прогресс,
 * таблица результатов по доменам, DPI-классификация.
 *
 * FIXES:
 * 1. Домены загружаются с сервера и отображаются в редактируемом textarea
 * 2. Timeout корректно показывается как блокировка (исправлено в backend)
 * 3. TCP 16-20KB результаты выводятся в отдельной секции
 * 4. DPI-классификация выводится в колонке таблицы для каждого домена
 * 5. Состояние формы сохраняется при переключении разделов
 */

const BlockcheckPage = (() => {
    /* ───────── state (сохраняется между переключениями) ───────── */
    let pollTimer = null;
    let lastStatus = null;
    let results = null;

    // Сохраняемое состояние формы (FIX #5)
    let savedMode = 'quick';
    let savedDomains = null;          // null = ещё не загружено
    let savedDomainsModified = false; // пользователь менял textarea
    let domainsLoaded = false;

    /* ───────── lifecycle ───────── */

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    Тестирование доступности
                </h1>
                <p class="page-description">Проверка блокировок и классификация DPI</p>
            </div>

            <!-- Панель управления -->
            <div class="card" id="bc-controls">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    Параметры
                </div>

                <div class="bc-form">
                    <div class="bc-form-row">
                        <div class="form-group" style="flex:1; min-width:200px;">
                            <label class="form-label">Режим</label>
                            <select class="form-select" id="bc-mode">
                                <option value="quick">Быстрый (quick)</option>
                                <option value="full">Полный (full)</option>
                                <option value="dpi_only">Только DPI</option>
                            </select>
                        </div>
                    </div>

                    <!-- FIX #1: Редактируемый список доменов -->
                    <div class="form-group">
                        <label class="form-label">
                            Домены для тестирования
                            <span style="font-weight:normal; color:var(--text-muted); font-size:11px; margin-left:6px;">
                                (по одному на строку, можно редактировать)
                            </span>
                        </label>
                        <textarea class="form-input" id="bc-domains" rows="8"
                                  placeholder="Загрузка..."
                                  style="font-family:var(--font-mono); font-size:12px; resize:vertical; line-height:1.6;"></textarea>
                        <div style="display:flex; gap:8px; margin-top:6px; align-items:center;">
                            <button class="btn btn-ghost btn-sm" id="bc-btn-save-domains" onclick="BlockcheckPage.saveDomains()" title="Сохранить список доменов">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить список
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="BlockcheckPage.resetDomains()" title="Сбросить к умолчаниям" style="color:var(--text-muted);">
                                Сбросить
                            </button>
                            <span id="bc-domains-status" style="font-size:11px; color:var(--text-muted); margin-left:auto;"></span>
                        </div>
                    </div>

                    <div class="bc-actions">
                        <button class="btn btn-primary" id="bc-btn-start" onclick="BlockcheckPage.start()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="5 3 19 12 5 21 5 3"/>
                            </svg>
                            Запустить
                        </button>
                        <button class="btn btn-ghost btn-sm hidden" id="bc-btn-stop" onclick="BlockcheckPage.stop()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="6" y="6" width="12" height="12" rx="1"/>
                            </svg>
                            Остановить
                        </button>
                    </div>
                </div>
            </div>

            <!-- Прогресс -->
            <div class="card hidden" id="bc-progress-card">
                <div class="card-title">Прогресс</div>
                <div class="bc-progress-info">
                    <span class="bc-phase" id="bc-phase">—</span>
                    <span class="bc-elapsed" id="bc-elapsed"></span>
                </div>
                <div class="diag-progress" style="margin-top:8px;">
                    <div class="diag-progress-bar" id="bc-progress-bar" style="width:0%"></div>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px;" id="bc-progress-detail"></div>
            </div>

            <!-- DPI-классификация -->
            <div class="card hidden" id="bc-dpi-card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    DPI-классификация
                </div>
                <div id="bc-dpi-info"></div>
            </div>

            <!-- Таблица результатов -->
            <div class="card hidden" id="bc-results-card">
                <div class="card-title">Результаты по доменам</div>
                <div id="bc-results-table"></div>
            </div>

            <!-- FIX #3: TCP 16-20KB результаты — отдельная секция -->
            <div class="card hidden" id="bc-tcp-card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                    TCP 16-20KB
                </div>
                <div id="bc-tcp-results"></div>
            </div>

            <!-- STUN результаты -->
            <div class="card hidden" id="bc-stun-card">
                <div class="card-title">STUN/UDP</div>
                <div id="bc-stun-results"></div>
            </div>
        `;

        // FIX #5: Восстановить сохранённое состояние формы
        const modeEl = document.getElementById('bc-mode');
        if (modeEl) modeEl.value = savedMode;

        // Загружаем домены
        loadDomains();

        // Проверяем текущий статус
        fetchStatus();
    }

    function destroy() {
        // FIX #5: Сохраняем состояние формы перед уничтожением
        _saveFormState();
        stopPolling();
    }

    function _saveFormState() {
        const modeEl = document.getElementById('bc-mode');
        if (modeEl) savedMode = modeEl.value;

        const domainsEl = document.getElementById('bc-domains');
        if (domainsEl && domainsEl.value.trim()) {
            savedDomains = domainsEl.value;
        }
    }

    /* ───────── FIX #1: Domains management ───────── */

    async function loadDomains() {
        const el = document.getElementById('bc-domains');
        const statusEl = document.getElementById('bc-domains-status');
        if (!el) return;

        // Если уже есть сохранённое состояние — восстанавливаем
        if (savedDomains !== null) {
            el.value = savedDomains;
            if (statusEl) statusEl.textContent = domainsLoaded ? '' : 'Загрузка...';
            if (domainsLoaded) return;
        }

        try {
            const data = await API.get('/api/blockcheck/domains');
            if (data.ok && data.domains) {
                const text = data.domains.join('\n');
                // Не перезаписываем если пользователь уже редактировал
                if (!savedDomainsModified) {
                    el.value = text;
                    savedDomains = text;
                }
                domainsLoaded = true;
                if (statusEl) {
                    statusEl.textContent = `${data.domains.length} доменов (${data.source || ''})`;
                }
            }
        } catch (err) {
            if (statusEl) statusEl.textContent = 'Ошибка загрузки';
            // Если нет сохранённого — показываем placeholder
            if (savedDomains === null) {
                el.placeholder = 'Не удалось загрузить список. Введите домены вручную.';
            }
        }
    }

    async function saveDomains() {
        const el = document.getElementById('bc-domains');
        if (!el) return;

        const lines = el.value.split('\n').map(s => s.trim()).filter(Boolean);
        if (lines.length === 0) {
            Toast.error('Список доменов пуст');
            return;
        }

        try {
            const res = await API.post('/api/blockcheck/domains', { domains: lines });
            if (res.ok) {
                Toast.success(`Сохранено ${res.count} доменов`);
                savedDomains = el.value;
                savedDomainsModified = false;
                const statusEl = document.getElementById('bc-domains-status');
                if (statusEl) statusEl.textContent = `${res.count} доменов сохранено`;
            } else {
                Toast.error(res.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function resetDomains() {
        // Перезагружаем с сервера, сбрасывая флаг модификации
        savedDomainsModified = false;
        savedDomains = null;
        domainsLoaded = false;
        await loadDomains();
        Toast.info('Список доменов сброшен');
    }

    /* ───────── Actions ───────── */

    async function start() {
        _saveFormState();

        const mode = savedMode;

        // Берём домены из textarea
        const domainsEl = document.getElementById('bc-domains');
        const domainsText = domainsEl ? domainsEl.value.trim() : '';
        const domainsList = domainsText
            ? domainsText.split('\n').map(s => s.trim()).filter(Boolean)
            : undefined;

        const body = { mode };
        if (domainsList && domainsList.length > 0) {
            body.domains = domainsList;
        }

        try {
            const res = await API.post('/api/blockcheck/start', body);
            if (res.ok) {
                Toast.success('Тестирование запущено');
                startPolling();
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function stop() {
        try {
            await API.post('/api/blockcheck/stop', {});
            Toast.info('Остановка запрошена');
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function fetchStatus() {
        try {
            const data = await API.get('/api/blockcheck/status');
            lastStatus = data;
            updateUI(data);

            if (data.status === 'running') {
                startPolling();
            } else {
                stopPolling();
                if (data.status === 'completed' || data.status === 'error' || data.status === 'cancelled') {
                    await fetchResults();
                }
            }
        } catch {
            // тихо
        }
    }

    async function fetchResults() {
        try {
            const data = await API.get('/api/blockcheck/results');
            if (data.ok && data.results) {
                results = data.results;
                renderResults(data.results);
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

        // Кнопки
        const btnStart = document.getElementById('bc-btn-start');
        const btnStop = document.getElementById('bc-btn-stop');
        if (btnStart) {
            btnStart.disabled = isRunning;
            btnStart.classList.toggle('btn-disabled', isRunning);
        }
        if (btnStop) {
            btnStop.classList.toggle('hidden', !isRunning);
        }

        // Прогресс
        const progressCard = document.getElementById('bc-progress-card');
        if (progressCard) {
            progressCard.classList.toggle('hidden', isIdle);
        }

        if (isRunning) {
            const pct = data.total > 0 ? Math.round((data.progress / data.total) * 100) : 0;
            const bar = document.getElementById('bc-progress-bar');
            if (bar) bar.style.width = pct + '%';

            const phase = document.getElementById('bc-phase');
            if (phase) phase.textContent = data.phase || '—';

            const detail = document.getElementById('bc-progress-detail');
            if (detail) detail.textContent = data.message || '';

            const elapsed = document.getElementById('bc-elapsed');
            if (elapsed) elapsed.textContent = formatElapsed(data.elapsed_seconds);
        }
    }

    /* ───────── Render results ───────── */

    function renderResults(r) {
        // Показываем карточки
        const dpiCard = document.getElementById('bc-dpi-card');
        const resCard = document.getElementById('bc-results-card');
        if (dpiCard) dpiCard.classList.remove('hidden');
        if (resCard) resCard.classList.remove('hidden');

        renderDPI(r);
        renderTable(r);
        renderTCP(r);
        renderSTUN(r);
    }

    function renderDPI(r) {
        const el = document.getElementById('bc-dpi-info');
        if (!el) return;

        const dpi = r.dpi_classification || 'none';
        const dpiLabels = {
            none:         { icon: '✅', text: 'DPI не обнаружен',              color: 'var(--success)' },
            dns_fake:     { icon: '🔀', text: 'DNS-подмена (fake IP)',         color: 'var(--warning)' },
            http_inject:  { icon: '💉', text: 'HTTP injection (DPI)',          color: 'var(--error)' },
            isp_page:     { icon: '🚫', text: 'ISP-заглушка',                 color: 'var(--error)' },
            tls_dpi:      { icon: '🔒', text: 'DPI по TLS (SNI/ClientHello)', color: 'var(--error)' },
            tls_mitm:     { icon: '⚠️', text: 'TLS MITM (подмена сертификата)', color: 'var(--error)' },
            tcp_reset:    { icon: '🔌', text: 'TCP RST (сброс соединения)',   color: 'var(--error)' },
            tcp_16_20:    { icon: '📦', text: 'TCP блок (16-20KB)',            color: 'var(--warning)' },
            stun_block:   { icon: '📡', text: 'STUN/UDP заблокирован',         color: 'var(--warning)' },
            full_block:   { icon: '⛔', text: 'Полная блокировка',             color: 'var(--error)' },
            timeout_drop: { icon: '⏳', text: 'Timeout/Drop пакетов',          color: 'var(--warning)' },
            unknown:      { icon: '❓', text: 'Неизвестный тип',               color: 'var(--text-muted)' },
        };

        const info = dpiLabels[dpi] || dpiLabels.unknown;

        el.innerHTML = `
            <div style="display:flex; align-items:center; gap:12px; padding:8px 0;">
                <span style="font-size:24px; color:${info.color};">${info.icon}</span>
                <div>
                    <div style="font-size:15px; font-weight:600; color:${info.color};">${info.text}</div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">
                        Тестов: ${r.total_tests || 0} | Успешно: ${r.passed_tests || 0} | Провалено: ${r.failed_tests || 0}
                    </div>
                </div>
            </div>
        `;

        // Рекомендации
        if (r.recommendations && r.recommendations.length > 0) {
            el.innerHTML += `
                <div style="margin-top:12px; padding:10px 14px; background:var(--bg-secondary); border-radius:var(--radius-sm); border:1px solid var(--border);">
                    <div style="font-size:12px; font-weight:500; color:var(--text-secondary); margin-bottom:6px;">Рекомендации</div>
                    ${r.recommendations.map(rec =>
                        `<div style="font-size:12px; color:var(--text-primary); padding:2px 0;">• ${escapeHtml(rec)}</div>`
                    ).join('')}
                </div>
            `;
        }
    }

    function renderTable(r) {
        const el = document.getElementById('bc-results-table');
        if (!el) return;

        const targets = r.targets || [];

        // Фильтруем только доменные цели (исключаем TCP, STUN, Ping IP)
        const domainTargets = targets.filter(t => {
            const d = t.domain || t.target || '';
            return d !== 'TCP 16-20KB'
                && !d.startsWith('Ping ')
                && !d.startsWith('Google STUN')
                && !d.startsWith('Cloudflare STUN')
                && !d.startsWith('Twilio STUN')
                && !d.startsWith('Telegram STUN');
        });

        if (domainTargets.length === 0) {
            el.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted);">Нет данных</div>';
            return;
        }

        // Определяем колонки по режиму
        const mode = r.mode || 'quick';
        const cols = [];
        if (mode !== 'quick') cols.push({ key: 'dns', label: 'DNS' });
        if (mode !== 'quick') cols.push({ key: 'tls12', label: 'TLS 1.2' });
        cols.push({ key: 'tls13', label: 'TLS 1.3' });
        if (mode !== 'quick') cols.push({ key: 'http', label: 'HTTP' });

        // FIX #4: Добавляем колонку «Тип DPI» для каждого домена
        let html = `
            <table class="bc-table">
                <thead>
                    <tr>
                        <th>Домен</th>
                        ${cols.map(c => `<th>${c.label}</th>`).join('')}
                        <th>Тип DPI</th>
                        <th>Статус</th>
                    </tr>
                </thead>
                <tbody>
        `;

        domainTargets.forEach(t => {
            const tests = t.tests || {};

            // FIX #4: DPI badge per domain
            const dpiClass = t.dpi_classification || 'none';
            const dpiBadge = dpiClassBadge(dpiClass, t.dpi_detail || '');

            html += `
                <tr>
                    <td class="bc-cell-domain">${escapeHtml(t.target || t.domain || '')}</td>
                    ${cols.map(c => `<td>${statusBadge(findTest(tests, c.key))}</td>`).join('')}
                    <td>${dpiBadge}</td>
                    <td>${overallBadge(t.overall_status || t.status)}</td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        el.innerHTML = html;
    }

    // FIX #3: TCP 16-20KB — отдельная секция
    function renderTCP(r) {
        const card = document.getElementById('bc-tcp-card');
        const el = document.getElementById('bc-tcp-results');
        if (!card || !el) return;

        const targets = r.targets || [];
        const tcpTarget = targets.find(t => (t.domain || t.target) === 'TCP 16-20KB');

        if (!tcpTarget || !tcpTarget.results || tcpTarget.results.length === 0) {
            card.classList.add('hidden');
            return;
        }

        card.classList.remove('hidden');

        const results = tcpTarget.results;
        let html = `
            <table class="bc-table">
                <thead>
                    <tr>
                        <th>URL / Провайдер</th>
                        <th>Статус</th>
                        <th>Задержка</th>
                        <th>Детали</th>
                    </tr>
                </thead>
                <tbody>
        `;

        results.forEach(r => {
            const provider = (r.raw_data && r.raw_data.provider) || '';
            const targetId = (r.raw_data && r.raw_data.target_id) || '';
            const label = provider ? `${provider} (${targetId})` : (r.target || '?');
            const st = r.status || 'pending';
            const badge = statusBadge(r);
            const latency = r.latency_ms ? `${Math.round(r.latency_ms)}ms` : '—';

            html += `
                <tr>
                    <td class="bc-cell-domain" title="${escapeHtml(r.target || '')}">${escapeHtml(label)}</td>
                    <td>${badge}</td>
                    <td style="font-family:var(--font-mono); font-size:11px;">${latency}</td>
                    <td style="font-size:11px; color:var(--text-muted); max-width:200px; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(r.details || '')}">${escapeHtml(r.details || '')}</td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        el.innerHTML = html;
    }

    // STUN results
    function renderSTUN(r) {
        const card = document.getElementById('bc-stun-card');
        const el = document.getElementById('bc-stun-results');
        if (!card || !el) return;

        const targets = r.targets || [];
        const stunTargets = targets.filter(t => {
            const d = t.domain || t.target || '';
            return d.includes('STUN');
        });

        if (stunTargets.length === 0) {
            card.classList.add('hidden');
            return;
        }

        card.classList.remove('hidden');

        let html = `<table class="bc-table"><thead><tr>
            <th>Сервер</th><th>Статус</th><th>Задержка</th><th>Детали</th>
        </tr></thead><tbody>`;

        stunTargets.forEach(t => {
            const test = t.results && t.results[0];
            const badge = test ? statusBadge(test) : '<span class="bc-badge bc-badge-skip">—</span>';
            const latency = test && test.latency_ms ? `${Math.round(test.latency_ms)}ms` : '—';
            const details = test ? (test.details || '') : '';

            html += `<tr>
                <td class="bc-cell-domain">${escapeHtml(t.domain || t.target || '')}</td>
                <td>${badge}</td>
                <td style="font-family:var(--font-mono); font-size:11px;">${latency}</td>
                <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(details)}</td>
            </tr>`;
        });

        html += '</tbody></table>';
        el.innerHTML = html;
    }

    /* ───────── Badge helpers ───────── */

    function findTest(tests, type) {
        // tests может быть объектом {dns: {...}, tls12: {...}} или массивом
        if (Array.isArray(tests)) {
            return tests.find(t => t.test_type === type || t.type === type);
        }
        return tests[type] || null;
    }

    function statusBadge(test) {
        if (!test) return '<span class="bc-badge bc-badge-skip">—</span>';
        const st = test.status || 'pending';
        const map = {
            success: { cls: 'bc-badge-ok', text: 'OK' },
            failed:  { cls: 'bc-badge-fail', text: 'Fail' },
            timeout: { cls: 'bc-badge-warn', text: 'Timeout' },
            error:   { cls: 'bc-badge-fail', text: 'Error' },
            skipped: { cls: 'bc-badge-skip', text: 'Skip' },
            pending: { cls: 'bc-badge-skip', text: '...' },
        };
        const info = map[st] || map.pending;
        const latency = test.latency_ms ? ` (${Math.round(test.latency_ms)}ms)` : '';
        return `<span class="bc-badge ${info.cls}" title="${escapeHtml(test.error || test.details || '')}">${info.text}${latency}</span>`;
    }

    function overallBadge(status) {
        if (!status) return '';
        const map = {
            accessible:   { cls: 'bc-badge-ok', text: 'Доступен' },
            blocked:      { cls: 'bc-badge-fail', text: 'Заблокирован' },
            partial:      { cls: 'bc-badge-warn', text: 'Частично' },
            dns_blocked:  { cls: 'bc-badge-fail', text: 'DNS-блок' },
            unknown:      { cls: 'bc-badge-skip', text: '?' },
        };
        const info = map[status] || { cls: 'bc-badge-skip', text: status };
        return `<span class="bc-badge ${info.cls}">${info.text}</span>`;
    }

    // FIX #4: DPI classification badge per domain
    function dpiClassBadge(dpiClass, detail) {
        if (!dpiClass || dpiClass === 'none') {
            return '<span class="bc-badge bc-badge-skip">—</span>';
        }
        const map = {
            dns_fake:     { cls: 'bc-badge-warn', text: 'DNS' },
            http_inject:  { cls: 'bc-badge-fail', text: 'HTTP inj' },
            isp_page:     { cls: 'bc-badge-fail', text: 'ISP' },
            tls_dpi:      { cls: 'bc-badge-fail', text: 'TLS DPI' },
            tls_mitm:     { cls: 'bc-badge-fail', text: 'TLS MITM' },
            tcp_reset:    { cls: 'bc-badge-fail', text: 'TCP RST' },
            tcp_16_20:    { cls: 'bc-badge-warn', text: 'TCP 16-20' },
            stun_block:   { cls: 'bc-badge-warn', text: 'STUN' },
            full_block:   { cls: 'bc-badge-fail', text: 'Full' },
            timeout_drop: { cls: 'bc-badge-warn', text: 'Timeout' },
            unknown:      { cls: 'bc-badge-skip', text: '?' },
        };
        const info = map[dpiClass] || { cls: 'bc-badge-skip', text: dpiClass };
        return `<span class="bc-badge ${info.cls}" title="${escapeHtml(detail)}">${info.text}</span>`;
    }

    /* ───────── helpers ───────── */

    function formatElapsed(sec) {
        if (!sec || sec < 0) return '';
        const m = Math.floor(sec / 60);
        const s = Math.round(sec % 60);
        return m > 0 ? `${m}м ${s}с` : `${s}с`;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /* ───────── public ───────── */

    return { render, destroy, start, stop, saveDomains, resetDomains };
})();
