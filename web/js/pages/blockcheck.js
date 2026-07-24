/**
 * blockcheck.js — Страница тестирования доступности (BlockCheck).
 *
 * Информативная диагностика DPI:
 *  - крупный вердикт-герой с рекомендацией по обходу (zapret/туннель/DNS);
 *  - сводная статистика по категориям тестов;
 *  - детальная таблица по доменам с разворачиваемыми строками
 *    (DNS / TLS1.2 / TLS1.3 / HTTP / QUIC / ClientHello / DPI / обход);
 *  - секция YouTube CDN (реальные шарды googlevideo + скорость/троттлинг);
 *  - Deep Trace (traceroute) по требованию — локализация рвущего хопа;
 *  - прокси (SOCKS5/HTTP) для сравнения «напрямую vs туннель»;
 *  - экспорт отчёта (JSON) и копирование сводки.
 */

const BlockcheckPage = (() => {
    /* ───────── state (сохраняется между переключениями) ───────── */
    let pollTimer = null;
    let lastStatus = null;
    let results = null;

    let savedMode = 'full';
    let savedDomains = null;
    let savedDomainsModified = false;
    let domainsLoaded = false;
    let proxyOpen = false;
    const traceCache = {};      // domain → trace result html state

    /* ───────── verdict / remediation metadata ───────── */

    const VERDICTS = {
        none:            { icon: '✅', text: 'DPI не обнаружен',                 cls: 'v-ok'   },
        dns_fake:        { icon: '🔀', text: 'DNS-подмена (fake IP)',            cls: 'v-warn' },
        http_inject:     { icon: '💉', text: 'HTTP injection (DPI)',            cls: 'v-bad'  },
        isp_page:        { icon: '🚫', text: 'ISP-заглушка',                     cls: 'v-bad'  },
        tls_dpi:         { icon: '🔒', text: 'DPI по TLS (SNI/ClientHello)',    cls: 'v-bad'  },
        tls_mitm:        { icon: '🕵️', text: 'TLS MITM (подмена сертификата)',  cls: 'v-bad'  },
        clienthello_dpi: { icon: '🧩', text: 'DPI по размеру ClientHello (PQ)', cls: 'v-bad'  },
        tcp_reset:       { icon: '🔌', text: 'TCP RST (сброс соединения)',      cls: 'v-bad'  },
        tcp_16_20:       { icon: '📦', text: 'TCP-блок на 16-20 КБ',            cls: 'v-warn' },
        stun_block:      { icon: '📡', text: 'STUN/UDP заблокирован',           cls: 'v-warn' },
        quic_block:      { icon: '🛸', text: 'QUIC/HTTP-3 (UDP 443) блокирован',cls: 'v-warn' },
        throttled:       { icon: '🐢', text: 'Троттлинг (замедление)',          cls: 'v-warn' },
        ip_block:        { icon: '🌐', text: 'Блок по IP (нужен туннель)',      cls: 'v-bad'  },
        full_block:      { icon: '⛔', text: 'Полная блокировка',               cls: 'v-bad'  },
        timeout_drop:    { icon: '⏳', text: 'Drop пакетов (timeout)',          cls: 'v-warn' },
        unknown:         { icon: '❓', text: 'Неизвестный тип',                  cls: 'v-skip' },
    };

    // Короткие метки для бейджа «Тип DPI» в таблице.
    const DPI_SHORT = {
        dns_fake: 'DNS', http_inject: 'HTTP inj', isp_page: 'ISP',
        tls_dpi: 'TLS DPI', tls_mitm: 'MITM', clienthello_dpi: 'CH size',
        tcp_reset: 'TCP RST', tcp_16_20: 'TCP 16-20', stun_block: 'STUN',
        quic_block: 'QUIC', throttled: 'Throttle', ip_block: 'IP block',
        full_block: 'Full', timeout_drop: 'Timeout', unknown: '?',
    };

    const REMEDIATION = {
        zapret:  { text: 'Обход DPI (zapret)', cls: 'rem-zapret' },
        tunnel:  { text: 'Нужен туннель',       cls: 'rem-tunnel' },
        dns:     { text: 'Настроить DNS',       cls: 'rem-dns' },
        none:    { text: 'Обход не нужен',      cls: 'rem-none' },
        unknown: { text: '—',                   cls: 'rem-skip' },
    };

    /* ───────── lifecycle ───────── */

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    Тестирование доступности${typeof Help !== 'undefined' ? Help.button('blockcheck') : ''}
                </h1>
                <p class="page-description">Проверка блокировок и классификация DPI — TLS, QUIC, ClientHello, CDN, троттлинг</p>
            </div>

            <!-- Панель управления -->
            <div class="card" id="bc-controls">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                    </svg>
                    Параметры
                </div>

                <div class="bc-form">
                    <div class="bc-form-row">
                        <div class="form-group" style="flex:1; min-width:200px;">
                            <label class="form-label">Режим</label>
                            <select class="form-select" id="bc-mode">
                                <option value="quick">Быстрый — TLS 1.3 + Ping</option>
                                <option value="dpi_only">DPI — TLS, ISP, TCP, ClientHello, QUIC</option>
                                <option value="full">Полный — всё + STUN, CDN, скорость</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">
                            Домены для тестирования
                            <span style="font-weight:normal; color:var(--text-muted); font-size:11px; margin-left:6px;">
                                (по одному на строку)
                            </span>
                        </label>
                        <textarea class="form-input" id="bc-domains" rows="7"
                                  placeholder="Загрузка..."
                                  style="font-family:var(--font-mono); font-size:12px; resize:vertical; line-height:1.6;"></textarea>
                        <div style="display:flex; gap:8px; margin-top:6px; align-items:center; flex-wrap:wrap;">
                            <button class="btn btn-ghost btn-sm" id="bc-btn-save-domains" onclick="BlockcheckPage.saveDomains()" title="Сохранить список доменов">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить список
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="BlockcheckPage.resetDomains()" title="Сбросить к умолчаниям" style="color:var(--text-muted);">Сбросить</button>
                            <button class="btn btn-ghost btn-sm" onclick="BlockcheckPage.toggleProxy()" id="bc-proxy-toggle" style="color:var(--text-muted);">⚙ Прокси</button>
                            <span id="bc-domains-status" style="font-size:11px; color:var(--text-muted); margin-left:auto;"></span>
                        </div>
                    </div>

                    <!-- Прокси (SOCKS5/HTTP) -->
                    <div class="bc-proxy-box hidden" id="bc-proxy-box">
                        <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                            Прогон TLS-проб через прокси — сравнить «напрямую» и «через туннель». UDP-тесты (QUIC/STUN/Ping) при этом пропускаются.
                        </div>
                        <div class="bc-proxy-grid">
                            <select class="form-select" id="bc-proxy-type">
                                <option value="">Без прокси</option>
                                <option value="socks5">SOCKS5</option>
                                <option value="http">HTTP CONNECT</option>
                            </select>
                            <input class="form-input" id="bc-proxy-host" placeholder="host (127.0.0.1)">
                            <input class="form-input" id="bc-proxy-port" placeholder="port" style="max-width:90px;">
                            <input class="form-input" id="bc-proxy-user" placeholder="логин (опц.)">
                            <input class="form-input" id="bc-proxy-pass" type="password" placeholder="пароль (опц.)">
                        </div>
                    </div>

                    <div class="bc-actions">
                        <button class="btn btn-primary" id="bc-btn-start" onclick="BlockcheckPage.start()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            Запустить
                        </button>
                        <button class="btn btn-ghost btn-sm hidden" id="bc-btn-stop" onclick="BlockcheckPage.stop()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>
                            Остановить
                        </button>
                        <button class="btn btn-ghost btn-sm hidden" id="bc-btn-export" onclick="BlockcheckPage.exportReport()" title="Скачать отчёт JSON">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Экспорт
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

            <!-- Вердикт-герой -->
            <div class="card hidden" id="bc-verdict-card"><div id="bc-verdict"></div></div>

            <!-- Сводная статистика -->
            <div class="card hidden" id="bc-stats-card">
                <div class="card-title">Сводка по тестам</div>
                <div id="bc-stats" class="bc-stats"></div>
            </div>

            <!-- Таблица результатов -->
            <div class="card hidden" id="bc-results-card">
                <div class="card-title">Результаты по доменам <span style="font-weight:normal;color:var(--text-muted);font-size:11px;">(нажмите строку для деталей и Deep Trace)</span></div>
                <div id="bc-results-table" class="bc-table-wrap"></div>
            </div>

            <!-- YouTube CDN -->
            <div class="card hidden" id="bc-cdn-card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22.54 6.42a2.78 2.78 0 0 0-1.94-2C18.88 4 12 4 12 4s-6.88 0-8.6.46a2.78 2.78 0 0 0-1.94 2A29 29 0 0 0 1 11.75a29 29 0 0 0 .46 5.33A2.78 2.78 0 0 0 3.4 19c1.72.46 8.6.46 8.6.46s6.88 0 8.6-.46a2.78 2.78 0 0 0 1.94-2 29 29 0 0 0 .46-5.25 29 29 0 0 0-.46-5.33z"/><polygon points="9.75 15.02 15.5 11.75 9.75 8.48 9.75 15.02"/></svg>
                    YouTube CDN (реальные шарды + скорость)
                </div>
                <div id="bc-cdn-results"></div>
            </div>

            <!-- TCP 16-20KB -->
            <div class="card hidden" id="bc-tcp-card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    TCP 16-20KB
                </div>
                <div id="bc-tcp-results"></div>
            </div>

            <!-- STUN результаты -->
            <div class="card hidden" id="bc-stun-card">
                <div class="card-title">STUN/UDP</div>
                <div id="bc-stun-results"></div>
            </div>

            <!-- Легенда -->
            <div class="card hidden" id="bc-legend-card">
                <div class="card-title">Что означают вердикты</div>
                <div id="bc-legend" class="bc-legend"></div>
            </div>
        `;

        const modeEl = document.getElementById('bc-mode');
        if (modeEl) modeEl.value = savedMode;
        if (proxyOpen) {
            const box = document.getElementById('bc-proxy-box');
            if (box) box.classList.remove('hidden');
        }

        loadDomains();
        fetchStatus();
    }

    function destroy() {
        _saveFormState();
        stopPolling();
    }

    function _saveFormState() {
        const modeEl = document.getElementById('bc-mode');
        if (modeEl) savedMode = modeEl.value;
        const domainsEl = document.getElementById('bc-domains');
        if (domainsEl && domainsEl.value.trim()) savedDomains = domainsEl.value;
    }

    /* ───────── Domains ───────── */

    async function loadDomains() {
        const el = document.getElementById('bc-domains');
        const statusEl = document.getElementById('bc-domains-status');
        if (!el) return;

        if (savedDomains !== null) {
            el.value = savedDomains;
            if (statusEl) statusEl.textContent = domainsLoaded ? '' : 'Загрузка...';
            if (domainsLoaded) return;
        }

        try {
            const data = await API.get('/api/blockcheck/domains');
            if (data.ok && data.domains) {
                const text = data.domains.join('\n');
                if (!savedDomainsModified) { el.value = text; savedDomains = text; }
                domainsLoaded = true;
                if (statusEl) statusEl.textContent = `${data.domains.length} доменов (${data.source || ''})`;
            }
        } catch (err) {
            if (statusEl) statusEl.textContent = 'Ошибка загрузки';
            if (savedDomains === null) el.placeholder = 'Не удалось загрузить список. Введите домены вручную.';
        }
    }

    async function saveDomains() {
        const el = document.getElementById('bc-domains');
        if (!el) return;
        const lines = el.value.split('\n').map(s => s.trim()).filter(Boolean);
        if (lines.length === 0) { Toast.error('Список доменов пуст'); return; }
        try {
            const res = await API.post('/api/blockcheck/domains', { domains: lines });
            if (res.ok) {
                Toast.success(`Сохранено ${res.count} доменов`);
                savedDomains = el.value; savedDomainsModified = false;
                const statusEl = document.getElementById('bc-domains-status');
                if (statusEl) statusEl.textContent = `${res.count} доменов сохранено`;
            } else Toast.error(res.error || 'Ошибка сохранения');
        } catch (err) { Toast.error(err.message); }
    }

    async function resetDomains() {
        savedDomainsModified = false; savedDomains = null; domainsLoaded = false;
        await loadDomains();
        Toast.info('Список доменов сброшен');
    }

    function toggleProxy() {
        proxyOpen = !proxyOpen;
        const box = document.getElementById('bc-proxy-box');
        if (box) box.classList.toggle('hidden', !proxyOpen);
    }

    function _readProxy() {
        const type = (document.getElementById('bc-proxy-type') || {}).value || '';
        if (!type) return null;
        const host = (document.getElementById('bc-proxy-host') || {}).value.trim();
        const port = (document.getElementById('bc-proxy-port') || {}).value.trim();
        if (!host || !port) { Toast.error('Укажите host и port прокси'); return undefined; }
        return {
            type, host, port: parseInt(port, 10) || 0,
            user: (document.getElementById('bc-proxy-user') || {}).value.trim(),
            pass: (document.getElementById('bc-proxy-pass') || {}).value,
        };
    }

    /* ───────── Actions ───────── */

    async function start() {
        _saveFormState();
        const mode = savedMode;
        const domainsEl = document.getElementById('bc-domains');
        const domainsText = domainsEl ? domainsEl.value.trim() : '';
        const domainsList = domainsText ? domainsText.split('\n').map(s => s.trim()).filter(Boolean) : undefined;

        const proxy = _readProxy();
        if (proxy === undefined) return; // ошибка валидации

        const body = { mode };
        if (domainsList && domainsList.length > 0) body.domains = domainsList;
        if (proxy) body.proxy = proxy;

        try {
            const res = await API.post('/api/blockcheck/start', body);
            if (res.ok) { Toast.success('Тестирование запущено'); startPolling(); }
            else Toast.error(res.error || 'Ошибка запуска');
        } catch (err) { Toast.error(err.message); }
    }

    async function stop() {
        try { await API.post('/api/blockcheck/stop', {}); Toast.info('Остановка запрошена'); }
        catch (err) { Toast.error(err.message); }
    }

    function exportReport() {
        if (!results) { Toast.error('Нет результатов'); return; }
        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `blockcheck-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
        document.body.appendChild(a); a.click();
        setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
    }

    async function fetchStatus() {
        try {
            const data = await API.get('/api/blockcheck/status');
            lastStatus = data;
            updateUI(data);
            if (data.status === 'running') startPolling();
            else {
                stopPolling();
                if (['completed', 'error', 'cancelled'].includes(data.status)) await fetchResults();
            }
        } catch { /* тихо */ }
    }

    async function fetchResults() {
        try {
            const data = await API.get('/api/blockcheck/results');
            if (data.ok && data.results) { results = data.results; renderResults(data.results); }
        } catch { /* тихо */ }
    }

    /* ───────── Polling ───────── */

    function startPolling() { if (!pollTimer) pollTimer = setInterval(fetchStatus, 2000); }
    function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

    /* ───────── UI update ───────── */

    function updateUI(data) {
        const isRunning = data.status === 'running';
        const isIdle = data.status === 'idle';

        const btnStart = document.getElementById('bc-btn-start');
        const btnStop = document.getElementById('bc-btn-stop');
        if (btnStart) { btnStart.disabled = isRunning; btnStart.classList.toggle('btn-disabled', isRunning); }
        if (btnStop) btnStop.classList.toggle('hidden', !isRunning);

        const progressCard = document.getElementById('bc-progress-card');
        if (progressCard) progressCard.classList.toggle('hidden', isIdle);

        if (isRunning) {
            const pct = data.total > 0 ? Math.round((data.progress / data.total) * 100) : 0;
            const bar = document.getElementById('bc-progress-bar');
            if (bar) bar.style.width = pct + '%';
            setText('bc-phase', data.phase || '—');
            setText('bc-progress-detail', data.message || '');
            setText('bc-elapsed', formatElapsed(data.elapsed_seconds));
        }
    }

    /* ───────── Render results ───────── */

    function renderResults(r) {
        ['bc-verdict-card', 'bc-stats-card', 'bc-results-card', 'bc-legend-card']
            .forEach(id => { const e = document.getElementById(id); if (e) e.classList.remove('hidden'); });
        const exp = document.getElementById('bc-btn-export');
        if (exp) exp.classList.remove('hidden');

        renderVerdict(r);
        renderStats(r);
        renderTable(r);
        renderCDN(r);
        renderTCP(r);
        renderSTUN(r);
        renderLegend();
    }

    function renderVerdict(r) {
        const el = document.getElementById('bc-verdict');
        if (!el) return;
        const dpi = r.dpi_classification || 'none';
        const v = VERDICTS[dpi] || VERDICTS.unknown;
        const rem = REMEDIATION[r.remediation] || REMEDIATION.unknown;
        const proxy = r.proxy_label ? `<span class="bc-chip bc-chip-muted" title="Проверка шла через прокси">через ${escapeHtml(r.proxy_label)}</span>` : '';

        el.innerHTML = `
            <div class="bc-verdict ${v.cls}">
                <div class="bc-verdict-icon">${v.icon}</div>
                <div class="bc-verdict-body">
                    <div class="bc-verdict-title">${v.text}</div>
                    <div class="bc-verdict-detail">${escapeHtml(r.dpi_detail || '')}</div>
                    <div class="bc-verdict-chips">
                        <span class="bc-chip ${rem.cls}">${rem.text}</span>
                        <span class="bc-chip bc-chip-muted">⏱ ${formatElapsed(r.elapsed_seconds)}</span>
                        <span class="bc-chip bc-chip-ok">✓ ${r.passed_tests || 0}</span>
                        <span class="bc-chip bc-chip-bad">✗ ${r.failed_tests || 0}</span>
                        <span class="bc-chip bc-chip-muted">${r.total_tests || 0} тестов</span>
                        ${proxy}
                    </div>
                </div>
            </div>
            ${(r.recommendations && r.recommendations.length) ? `
                <div class="bc-recs">
                    ${r.recommendations.map(rec => `<div class="bc-rec">💡 ${escapeHtml(rec)}</div>`).join('')}
                </div>` : ''}
        `;
    }

    function renderStats(r) {
        const el = document.getElementById('bc-stats');
        if (!el) return;
        const acc = {}; // type → {ok, fail}
        const bump = (k, ok) => { acc[k] = acc[k] || { ok: 0, fail: 0 }; acc[k][ok ? 'ok' : 'fail']++; };
        (r.targets || []).forEach(t => (t.results || []).forEach(res => {
            const ok = res.status === 'success';
            if (res.status === 'skipped' || res.status === 'pending') return;
            bump(res.test_type, ok);
        }));
        const LABEL = {
            dns: 'DNS', http: 'HTTP', tls12: 'TLS 1.2', tls13: 'TLS 1.3',
            quic: 'QUIC', tls_bighello: 'ClientHello PQ', stun: 'STUN',
            tcp_16_20: 'TCP 16-20', ping: 'Ping', isp_detect: 'ISP', http_inject: 'HTTP inj',
        };
        const order = ['dns', 'http', 'tls12', 'tls13', 'quic', 'tls_bighello', 'tcp_16_20', 'stun', 'ping', 'isp_detect', 'http_inject'];
        const keys = order.filter(k => acc[k]).concat(Object.keys(acc).filter(k => !order.includes(k)));
        el.innerHTML = keys.map(k => {
            const s = acc[k]; const total = s.ok + s.fail;
            const pct = total ? Math.round(s.ok / total * 100) : 0;
            const cls = pct === 100 ? 'v-ok' : (pct === 0 ? 'v-bad' : 'v-warn');
            return `<div class="bc-stat ${cls}">
                <div class="bc-stat-label">${LABEL[k] || k}</div>
                <div class="bc-stat-val">${s.ok}/${total}</div>
                <div class="bc-stat-bar"><div style="width:${pct}%"></div></div>
            </div>`;
        }).join('') || '<div style="color:var(--text-muted);padding:8px;">Нет данных</div>';
    }

    function isServiceTarget(d) {
        return d === 'TCP 16-20KB' || d === 'YouTube CDN'
            || d.startsWith('Ping ') || d.includes('STUN');
    }

    function renderTable(r) {
        const el = document.getElementById('bc-results-table');
        if (!el) return;
        const mode = r.mode || 'quick';
        const domainTargets = (r.targets || []).filter(t => !isServiceTarget(t.domain || t.target || ''));
        if (!domainTargets.length) { el.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-muted);">Нет данных</div>'; return; }

        const cols = [];
        if (mode !== 'quick') cols.push({ key: 'dns', label: 'DNS' });
        if (mode !== 'quick') cols.push({ key: 'tls12', label: 'TLS 1.2' });
        cols.push({ key: 'tls13', label: 'TLS 1.3' });
        if (mode !== 'quick') cols.push({ key: 'http', label: 'HTTP' });
        if (mode !== 'quick') cols.push({ key: 'tls_bighello', label: 'CH PQ' });
        if (mode !== 'quick') cols.push({ key: 'quic', label: 'QUIC' });

        let html = `<table class="bc-table"><thead><tr>
            <th style="width:18px;"></th><th>Домен</th>
            ${cols.map(c => `<th>${c.label}</th>`).join('')}
            <th>Тип DPI</th><th>Обход</th><th>Статус</th>
        </tr></thead><tbody>`;

        domainTargets.forEach((t, i) => {
            const tests = t.tests || {};
            const dpiClass = t.dpi_classification || 'none';
            const rowId = `bc-row-${i}`;
            html += `<tr class="bc-row" onclick="BlockcheckPage.toggleRow('${rowId}')">
                <td class="bc-caret" id="${rowId}-caret">▸</td>
                <td class="bc-cell-domain">${escapeHtml(t.target || t.domain || '')}</td>
                ${cols.map(c => `<td>${statusBadge(findTest(tests, c.key))}</td>`).join('')}
                <td>${dpiClassBadge(dpiClass, t.dpi_detail || '')}</td>
                <td>${remChip(t.remediation)}</td>
                <td>${overallBadge(t.overall_status || t.status)}</td>
            </tr>
            <tr class="bc-detail-row hidden" id="${rowId}-detail"><td colspan="${cols.length + 5}">
                ${renderDomainDetail(t)}
            </td></tr>`;
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function renderDomainDetail(t) {
        const rows = (t.results || []).map(res => {
            const lat = res.latency_ms ? `${Math.round(res.latency_ms)} ms` : '—';
            return `<tr>
                <td style="font-family:var(--font-mono);">${escapeHtml(res.test_type)}</td>
                <td>${statusBadge(res)}</td>
                <td style="font-family:var(--font-mono);color:var(--text-muted);">${lat}</td>
                <td style="color:var(--text-muted);">${escapeHtml(res.error || '')}</td>
                <td style="color:var(--text-secondary);">${escapeHtml(res.details || '')}</td>
            </tr>`;
        }).join('');
        const domain = escapeHtml(t.target || t.domain || '');
        return `
            <div class="bc-detail">
                <table class="bc-subtable">
                    <thead><tr><th>Тест</th><th>Статус</th><th>Задержка</th><th>Код</th><th>Детали</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
                <div class="bc-trace-block">
                    <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();BlockcheckPage.traceroute('${domain}')">
                        🛰 Deep Trace (traceroute)
                    </button>
                    <span style="font-size:11px;color:var(--text-muted);margin-left:8px;">локализация хопа, рвущего соединение</span>
                    <div id="bc-trace-${cssId(domain)}" class="bc-trace-out"></div>
                </div>
            </div>`;
    }

    function renderCDN(r) {
        const card = document.getElementById('bc-cdn-card');
        const el = document.getElementById('bc-cdn-results');
        if (!card || !el) return;
        const cdn = (r.targets || []).find(t => (t.domain || t.target) === 'YouTube CDN');
        if (!cdn || !cdn.results || !cdn.results.length) { card.classList.add('hidden'); return; }
        card.classList.remove('hidden');

        // Группируем TLS-результаты по шарду + ищем throughput.
        const shards = {}; let thr = null;
        cdn.results.forEach(res => {
            if (res.error === 'THROTTLE_SLOW' || (res.raw_data && res.raw_data.throughput_probe) || (res.raw_data && res.raw_data.throttle)) { thr = res; return; }
            if (res.test_type === 'http' && res.target && res.target.includes('ytimg')) { thr = res; return; }
            const host = res.target || '?';
            shards[host] = shards[host] || {};
            shards[host][res.test_type] = res;
        });

        let html = '';
        if (thr) {
            const kbps = (thr.raw_data && thr.raw_data.kbps) || 0;
            const throttled = thr.error === 'THROTTLE_SLOW' || (thr.raw_data && thr.raw_data.throttle);
            html += `<div class="bc-throughput ${throttled ? 'v-warn' : 'v-ok'}">
                <div style="font-size:12px;color:var(--text-muted);">Скорость загрузки (i.ytimg.com)</div>
                <div style="font-size:20px;font-weight:600;">${kbps ? kbps.toFixed(1) : '—'} <span style="font-size:12px;">KB/s</span>
                    ${throttled ? '<span class="bc-chip rem-zapret" style="margin-left:8px;">🐢 троттлинг</span>' : ''}</div>
                <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(thr.details || '')}</div>
            </div>`;
        }

        const hostKeys = Object.keys(shards);
        if (hostKeys.length) {
            html += `<table class="bc-table" style="margin-top:10px;"><thead><tr>
                <th>Реальный шард googlevideo</th><th>TLS 1.2</th><th>TLS 1.3</th>
            </tr></thead><tbody>`;
            hostKeys.forEach(h => {
                html += `<tr>
                    <td class="bc-cell-domain">${escapeHtml(h)}</td>
                    <td>${statusBadge(shards[h]['tls12'])}</td>
                    <td>${statusBadge(shards[h]['tls13'])}</td>
                </tr>`;
            });
            html += '</tbody></table>';
        }
        if (cdn.summary) html += `<div style="font-size:11px;color:var(--text-muted);margin-top:6px;">${escapeHtml(cdn.summary)}</div>`;
        el.innerHTML = html || '<div style="color:var(--text-muted);padding:8px;">Нет данных</div>';
    }

    function renderTCP(r) {
        const card = document.getElementById('bc-tcp-card');
        const el = document.getElementById('bc-tcp-results');
        if (!card || !el) return;
        const tcp = (r.targets || []).find(t => (t.domain || t.target) === 'TCP 16-20KB');
        if (!tcp || !tcp.results || !tcp.results.length) { card.classList.add('hidden'); return; }
        card.classList.remove('hidden');
        let html = `<table class="bc-table"><thead><tr><th>URL / Провайдер</th><th>Статус</th><th>Задержка</th><th>Детали</th></tr></thead><tbody>`;
        tcp.results.forEach(res => {
            const provider = (res.raw_data && res.raw_data.provider) || '';
            const targetId = (res.raw_data && res.raw_data.target_id) || '';
            const label = provider ? `${provider} (${targetId})` : (res.target || '?');
            const latency = res.latency_ms ? `${Math.round(res.latency_ms)}ms` : '—';
            html += `<tr>
                <td class="bc-cell-domain" title="${escapeHtml(res.target || '')}">${escapeHtml(label)}</td>
                <td>${statusBadge(res)}</td>
                <td style="font-family:var(--font-mono);font-size:11px;">${latency}</td>
                <td style="font-size:11px;color:var(--text-muted);max-width:240px;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(res.details || '')}">${escapeHtml(res.details || '')}</td>
            </tr>`;
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function renderSTUN(r) {
        const card = document.getElementById('bc-stun-card');
        const el = document.getElementById('bc-stun-results');
        if (!card || !el) return;
        const stun = (r.targets || []).filter(t => (t.domain || t.target || '').includes('STUN'));
        if (!stun.length) { card.classList.add('hidden'); return; }
        card.classList.remove('hidden');
        let html = `<table class="bc-table"><thead><tr><th>Сервер</th><th>Статус</th><th>Задержка</th><th>Детали</th></tr></thead><tbody>`;
        stun.forEach(t => {
            const test = t.results && t.results[0];
            const latency = test && test.latency_ms ? `${Math.round(test.latency_ms)}ms` : '—';
            html += `<tr>
                <td class="bc-cell-domain">${escapeHtml(t.domain || t.target || '')}</td>
                <td>${test ? statusBadge(test) : '<span class="bc-badge bc-badge-skip">—</span>'}</td>
                <td style="font-family:var(--font-mono);font-size:11px;">${latency}</td>
                <td style="font-size:11px;color:var(--text-muted);">${escapeHtml(test ? (test.details || '') : '')}</td>
            </tr>`;
        });
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function renderLegend() {
        const el = document.getElementById('bc-legend');
        if (!el || el.dataset.done) return;
        el.dataset.done = '1';
        el.innerHTML = Object.entries(VERDICTS).filter(([k]) => k !== 'unknown').map(([k, v]) =>
            `<div class="bc-legend-item"><span>${v.icon}</span><span>${v.text}</span></div>`
        ).join('');
    }

    /* ───────── Deep Trace ───────── */

    async function traceroute(domain) {
        const out = document.getElementById('bc-trace-' + cssId(domain));
        if (!out) return;
        out.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:6px 0;">🛰 Трассировка... (до ~40с)</div>';
        try {
            // Traceroute синхронный и может идти до ~45с — свой таймаут выше
            // дефолтных 15с, иначе фронт оборвёт легитимную трассировку.
            const res = await API.post('/api/blockcheck/traceroute', { host: domain }, { timeout: 60000 });
            if (!res.ok || !res.result) { out.innerHTML = `<div class="bc-trace-err">Ошибка: ${escapeHtml(res.error || 'нет данных')}</div>`; return; }
            out.innerHTML = renderTrace(res.result);
        } catch (err) {
            out.innerHTML = `<div class="bc-trace-err">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    function renderTrace(tr) {
        if (tr.error && (!tr.hops || !tr.hops.length)) {
            return `<div class="bc-trace-err">traceroute недоступен: ${escapeHtml(tr.error)}</div>`;
        }
        const hops = tr.hops || [];
        // Последний ответивший хоп — кандидат на «обрыв», если цель не достигнута.
        let lastResp = -1;
        hops.forEach((h, i) => { if (h.ip) lastResp = i; });
        const breakIdx = tr.reached ? -1 : lastResp;

        const meta = `<div class="bc-trace-meta">метод: ${escapeHtml(tr.method || '?')} · цель: ${escapeHtml(tr.target_ip || tr.host)} · ${tr.reached ? '<span style="color:var(--success)">достигнута</span>' : '<span style="color:var(--warning)">не достигнута</span>'}</div>`;

        const rows = hops.map((h, i) => {
            const cls = h.timeout ? 'hop-to' : (i === breakIdx ? 'hop-break' : 'hop-ok');
            const ip = h.timeout ? '* * *' : (h.ip || '?');
            const rtt = h.rtt_ms != null ? `${h.rtt_ms} ms` : '';
            const ann = h.annotation ? ` <span class="hop-ann">${escapeHtml(h.annotation)}</span>` : '';
            const flag = (i === breakIdx && !h.timeout) ? ' ⛔ возможный обрыв' : '';
            return `<div class="bc-hop ${cls}"><span class="hop-n">${h.hop}</span><span class="hop-ip">${escapeHtml(ip)}</span><span class="hop-rtt">${rtt}</span>${ann}<span class="hop-flag">${flag}</span></div>`;
        }).join('');
        return meta + `<div class="bc-trace-list">${rows}</div>`;
    }

    function toggleRow(rowId) {
        const detail = document.getElementById(rowId + '-detail');
        const caret = document.getElementById(rowId + '-caret');
        if (!detail) return;
        const hidden = detail.classList.toggle('hidden');
        if (caret) caret.textContent = hidden ? '▸' : '▾';
    }

    /* ───────── Badge helpers ───────── */

    function findTest(tests, type) {
        if (Array.isArray(tests)) return tests.find(t => t.test_type === type || t.type === type);
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
            accessible:  { cls: 'bc-badge-ok', text: 'Доступен' },
            blocked:     { cls: 'bc-badge-fail', text: 'Заблокирован' },
            partial:     { cls: 'bc-badge-warn', text: 'Частично' },
            dns_blocked: { cls: 'bc-badge-fail', text: 'DNS-блок' },
            unknown:     { cls: 'bc-badge-skip', text: '?' },
        };
        const info = map[status] || { cls: 'bc-badge-skip', text: status };
        return `<span class="bc-badge ${info.cls}">${info.text}</span>`;
    }

    function dpiClassBadge(dpiClass, detail) {
        if (!dpiClass || dpiClass === 'none') return '<span class="bc-badge bc-badge-skip">—</span>';
        const v = VERDICTS[dpiClass] || VERDICTS.unknown;
        const cls = v.cls === 'v-bad' ? 'bc-badge-fail' : (v.cls === 'v-warn' ? 'bc-badge-warn' : 'bc-badge-skip');
        return `<span class="bc-badge ${cls}" title="${escapeHtml(detail)}">${DPI_SHORT[dpiClass] || dpiClass}</span>`;
    }

    function remChip(rem) {
        if (!rem || rem === 'none') return '<span class="bc-badge bc-badge-skip">—</span>';
        const info = REMEDIATION[rem] || REMEDIATION.unknown;
        return `<span class="bc-chip ${info.cls}" style="font-size:10px;padding:1px 7px;">${info.text}</span>`;
    }

    /* ───────── helpers ───────── */

    function setText(id, txt) { const e = document.getElementById(id); if (e) e.textContent = txt; }
    function cssId(s) { return (s || '').replace(/[^a-z0-9]/gi, '_'); }
    function formatElapsed(sec) {
        if (!sec || sec < 0) return '0с';
        const m = Math.floor(sec / 60), s = Math.round(sec % 60);
        return m > 0 ? `${m}м ${s}с` : `${s}с`;
    }
    function escapeHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        render, destroy, start, stop, saveDomains, resetDomains,
        toggleProxy, exportReport, toggleRow, traceroute,
    };
})();
