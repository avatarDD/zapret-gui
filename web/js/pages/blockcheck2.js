/**
 * blockcheck2.js — Страница «BlockCheck2 (официальный)».
 *
 * Запускает ШТАТНЫЙ скрипт blockcheck2.sh / blockcheck.sh из zapret2
 * (bol-van) как подпроцесс и стримит его вывод (телеметрию) в реальном
 * времени. В отличие от «BlockCheck(mod)» (наш сканер каталога) и
 * «Тестирование доступности» (наш Python-тестер), здесь работает сам
 * оригинальный инструмент zapret2.
 *
 * Параметры передаются скрипту через окружение в неинтерактивном режиме
 * (BATCH=1): DOMAINS, IPVS, SCANLEVEL, ENABLE_*, SKIP_*, REPEATS, PARALLEL,
 * CURL_VERBOSE + произвольные KEY=VALUE и доп. аргументы.
 *
 * API: /api/blockcheck2/{script,start,status,output,stop}.
 */

const Blockcheck2Page = (() => {
    /* ───────── state (сохраняется между переключениями) ───────── */
    let pollTimer = null;
    let outOffset = 0;            // next_offset для инкрементального вывода
    let scriptPath = null;
    let scriptFound = false;

    /* ───────── lifecycle ───────── */

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
                    </svg>
                    BlockCheck2 (официальный)${typeof Help !== 'undefined' ? Help.button('blockcheck2') : ''}
                </h1>
                <p class="page-description">Запуск штатного blockcheck2.sh из zapret2 с потоковой телеметрией</p>
            </div>

            <!-- Статус скрипта -->
            <div class="card" id="bc2-script-card">
                <div id="bc2-script-info" style="font-size:13px;color:var(--text-muted);">Поиск скрипта…</div>
            </div>

            <!-- Параметры -->
            <div class="card" id="bc2-controls">
                <div class="card-title">Параметры запуска</div>
                <div class="bc-form">
                    <div class="form-group">
                        <label class="form-label">
                            Домены
                            <span style="font-weight:normal;color:var(--text-muted);font-size:11px;margin-left:6px;">
                                (по одному на строку; пусто → дефолт скрипта)
                            </span>
                        </label>
                        <textarea class="form-input" id="bc2-domains" rows="4"
                                  placeholder="rutracker.org&#10;youtube.com"
                                  style="font-family:var(--font-mono);font-size:12px;resize:vertical;line-height:1.6;"></textarea>
                    </div>

                    <div class="bc2-grid">
                        <div class="form-group">
                            <label class="form-label">Уровень сканирования (SCANLEVEL)</label>
                            <select class="form-select" id="bc2-scanlevel">
                                <option value="">по умолчанию</option>
                                <option value="quick">quick</option>
                                <option value="standard" selected>standard</option>
                                <option value="force">force</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">IP-версия (IPVS)</label>
                            <select class="form-select" id="bc2-ipvs">
                                <option value="4" selected>IPv4</option>
                                <option value="6">IPv6</option>
                                <option value="46">IPv4 + IPv6</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Повторы (REPEATS)</label>
                            <input class="form-input" id="bc2-repeats" type="number" min="1" max="20" placeholder="дефолт">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Протоколы для проверки</label>
                        <div class="bc2-checks">
                            <label class="bc2-check"><input type="checkbox" id="bc2-http"> HTTP</label>
                            <label class="bc2-check"><input type="checkbox" id="bc2-tls12"> HTTPS TLS 1.2</label>
                            <label class="bc2-check"><input type="checkbox" id="bc2-tls13" checked> HTTPS TLS 1.3</label>
                            <label class="bc2-check"><input type="checkbox" id="bc2-http3"> HTTP/3 (QUIC)</label>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Дополнительно</label>
                        <div class="bc2-checks">
                            <label class="bc2-check" title="CURL_HTTPS_GET=1 — качать всё тело сайта (GET) вместо заголовков (HEAD, -I). Ловит блокировку, когда DPI пускает первые ~16-20 КБ и обрывает соединение.">
                                <input type="checkbox" id="bc2-https-get"> Качать полное тело (обход блока по ~20КБ)
                            </label>
                            <label class="bc2-check" title="SKIP_PKTWS — не тестировать pkt-движок (nfqws2).">
                                <input type="checkbox" id="bc2-skip-pktws"> SKIP_PKTWS
                            </label>
                            <label class="bc2-check" title="SKIP_IPBLOCK — пропустить проверку блокировки по IP.">
                                <input type="checkbox" id="bc2-skip-ipblock"> SKIP_IPBLOCK
                            </label>
                            <label class="bc2-check" title="SKIP_DNSCHECK — пропустить проверку подмены DNS.">
                                <input type="checkbox" id="bc2-skip-dnscheck"> SKIP_DNSCHECK
                            </label>
                            <label class="bc2-check" title="PARALLEL=1 — параллельный прогон тестов (быстрее, вывод вперемешку).">
                                <input type="checkbox" id="bc2-parallel"> PARALLEL
                            </label>
                            <label class="bc2-check" title="CURL_VERBOSE=1 — подробный вывод curl.">
                                <input type="checkbox" id="bc2-curl-verbose"> CURL_VERBOSE
                            </label>
                        </div>
                    </div>

                    <details id="bc2-advanced">
                        <summary style="cursor:pointer;font-size:13px;color:var(--text-secondary);">Расширенные параметры</summary>
                        <div class="form-group" style="margin-top:10px;">
                            <label class="form-label">Доп. переменные окружения
                                <span style="font-weight:normal;color:var(--text-muted);font-size:11px;margin-left:6px;">(KEY=VALUE, по одной на строку)</span>
                            </label>
                            <textarea class="form-input" id="bc2-env" rows="3"
                                      placeholder="HSTART=1&#10;DELAY=2"
                                      style="font-family:var(--font-mono);font-size:12px;resize:vertical;"></textarea>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Доп. аргументы скрипта
                                <span style="font-weight:normal;color:var(--text-muted);font-size:11px;margin-left:6px;">(через пробел)</span>
                            </label>
                            <input class="form-input" id="bc2-args" placeholder="" style="font-family:var(--font-mono);font-size:12px;">
                        </div>
                    </details>

                    <div class="bc-actions">
                        <button class="btn btn-primary" id="bc2-btn-start" onclick="Blockcheck2Page.start()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            Запустить
                        </button>
                        <button class="btn btn-ghost btn-sm hidden" id="bc2-btn-stop" onclick="Blockcheck2Page.stop()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>
                            Остановить
                        </button>
                        <button class="btn btn-ghost btn-sm" id="bc2-btn-clear" onclick="Blockcheck2Page.clearOutput()">Очистить вывод</button>
                        <span id="bc2-run-status" style="font-size:12px;color:var(--text-muted);margin-left:auto;"></span>
                    </div>
                </div>
            </div>

            <!-- Телеметрия -->
            <div class="card" id="bc2-output-card">
                <div class="card-title">Телеметрия blockcheck</div>
                <div class="bc2-highlights" id="bc2-highlights"></div>
                <pre class="bc2-term" id="bc2-term"></pre>
            </div>
        `;

        loadScript();
        // Подтянуть текущее состояние (вдруг запуск уже идёт).
        outOffset = 0;
        fetchStatus(true);
    }

    function destroy() { stopPolling(); }

    /* ───────── script discovery ───────── */

    async function loadScript() {
        const el = document.getElementById('bc2-script-info');
        try {
            const data = await API.get('/api/blockcheck2/script');
            scriptFound = !!(data && data.found);
            scriptPath = data && data.script;
            if (scriptFound) {
                el.innerHTML = `Скрипт: <code style="color:var(--text-secondary);">${escapeHtml(scriptPath)}</code>`;
            } else {
                el.innerHTML = `<span style="color:var(--warning,#fbbf24);">⚠ Скрипт blockcheck не найден.</span> ` +
                    `Установите zapret2 или задайте путь в Настройки → <code>zapret.blockcheck2_path</code>.`;
            }
            const btn = document.getElementById('bc2-btn-start');
            if (btn) { btn.disabled = !scriptFound; btn.classList.toggle('btn-disabled', !scriptFound); }
        } catch (err) {
            el.textContent = 'Ошибка проверки скрипта: ' + err.message;
        }
    }

    /* ───────── build params ───────── */

    function _buildBody() {
        const domainsText = (document.getElementById('bc2-domains') || {}).value || '';
        const domains = domainsText.split('\n').map(s => s.trim()).filter(Boolean);

        const scanlevel = (document.getElementById('bc2-scanlevel') || {}).value || '';

        const params = {};
        const ipvs = (document.getElementById('bc2-ipvs') || {}).value;
        if (ipvs) params.IPVS = ipvs;

        const repeats = (document.getElementById('bc2-repeats') || {}).value.trim();
        if (repeats) params.REPEATS = repeats;

        // Протоколы — отправляем явные 0/1.
        params.ENABLE_HTTP = _chk('bc2-http') ? '1' : '0';
        params.ENABLE_HTTPS_TLS12 = _chk('bc2-tls12') ? '1' : '0';
        params.ENABLE_HTTPS_TLS13 = _chk('bc2-tls13') ? '1' : '0';
        params.ENABLE_HTTP3 = _chk('bc2-http3') ? '1' : '0';

        // CURL_HTTPS_GET=1 — GET всего тела вместо HEAD (обход блока по ~20КБ).
        if (_chk('bc2-https-get')) params.CURL_HTTPS_GET = '1';
        if (_chk('bc2-skip-pktws')) params.SKIP_PKTWS = '1';
        if (_chk('bc2-skip-ipblock')) params.SKIP_IPBLOCK = '1';
        if (_chk('bc2-skip-dnscheck')) params.SKIP_DNSCHECK = '1';
        if (_chk('bc2-parallel')) params.PARALLEL = '1';
        if (_chk('bc2-curl-verbose')) params.CURL_VERBOSE = '1';

        // Доп. env (KEY=VALUE построчно).
        const envText = (document.getElementById('bc2-env') || {}).value || '';
        envText.split('\n').forEach(line => {
            const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
            if (m) params[m[1].toUpperCase()] = m[2].trim();
        });

        const argsRaw = (document.getElementById('bc2-args') || {}).value.trim();
        const extra_args = argsRaw ? argsRaw.split(/\s+/) : undefined;

        const body = { params };
        if (domains.length) body.domains = domains;
        if (scanlevel) body.scanlevel = scanlevel;
        if (extra_args) body.extra_args = extra_args;
        return body;
    }

    function _chk(id) { const e = document.getElementById(id); return !!(e && e.checked); }

    /* ───────── actions ───────── */

    async function start() {
        if (!scriptFound) { Toast.error('Скрипт blockcheck не найден'); return; }
        const body = _buildBody();
        try {
            const res = await API.post('/api/blockcheck2/start', body);
            if (res.ok) {
                Toast.success('blockcheck запущен');
                // Новый прогон — чистим вывод и offset.
                clearOutput();
                startPolling();
            } else {
                Toast.error(res.error || 'Ошибка запуска');
            }
        } catch (err) { Toast.error(err.message); }
    }

    async function stop() {
        try { await API.post('/api/blockcheck2/stop', {}); Toast.info('Остановка запрошена'); }
        catch (err) { Toast.error(err.message); }
    }

    function clearOutput() {
        outOffset = 0;
        const term = document.getElementById('bc2-term');
        if (term) term.textContent = '';
        const hl = document.getElementById('bc2-highlights');
        if (hl) hl.innerHTML = '';
    }

    /* ───────── polling ───────── */

    function startPolling() {
        if (!pollTimer) pollTimer = setInterval(tick, 1200);
        tick();
    }
    function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

    async function tick() {
        await fetchOutput();
        await fetchStatus(false);
    }

    async function fetchStatus(initial) {
        try {
            const s = await API.get('/api/blockcheck2/status');
            const running = !!s.running;

            const btnStart = document.getElementById('bc2-btn-start');
            const btnStop = document.getElementById('bc2-btn-stop');
            if (btnStart) { btnStart.disabled = running || !scriptFound; btnStart.classList.toggle('btn-disabled', running || !scriptFound); }
            if (btnStop) btnStop.classList.toggle('hidden', !running);

            renderHighlights(s.highlights || []);

            const statusEl = document.getElementById('bc2-run-status');
            if (statusEl) {
                if (running) {
                    statusEl.textContent = `⏳ выполняется · ${formatElapsed(s.elapsed_seconds)} · ${s.line_count || 0} строк`;
                } else if (s.started) {
                    const code = s.exit_code;
                    const mark = code === 0 ? '✓' : '⚠';
                    statusEl.textContent = `${mark} завершено (exit=${code == null ? '?' : code}) · ${formatElapsed(s.elapsed_seconds)} · ${s.line_count || 0} строк`;
                } else {
                    statusEl.textContent = '';
                }
            }

            if (initial && running) startPolling();
            if (!running) {
                // финальный добор вывода и стоп.
                await fetchOutput();
                stopPolling();
            }
        } catch { /* тихо */ }
    }

    async function fetchOutput() {
        try {
            const data = await API.get('/api/blockcheck2/output?offset=' + outOffset);
            if (data && Array.isArray(data.lines) && data.lines.length) {
                appendLines(data.lines);
            }
            if (data && typeof data.next_offset === 'number') outOffset = data.next_offset;
        } catch { /* тихо */ }
    }

    /* ───────── render ───────── */

    function appendLines(lines) {
        const term = document.getElementById('bc2-term');
        if (!term) return;
        const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
        const frag = document.createDocumentFragment();
        lines.forEach(line => {
            const span = document.createElement('span');
            span.className = lineClass(line);
            span.textContent = line + '\n';
            frag.appendChild(span);
        });
        term.appendChild(frag);
        if (atBottom) term.scrollTop = term.scrollHeight;
    }

    function lineClass(line) {
        if (/working strategy found/i.test(line)) return 'ln-hl';
        // UNAVAILABLE проверяем РАНЬШE AVAILABLE (это её подстрока).
        if (/UNAVAILABLE|BLOCK|FAIL|error|ошиб|недоступ/i.test(line)) return 'ln-bad';
        if (/\bAVAILABLE\b|\bOK\b|success|доступ/i.test(line)) return 'ln-ok';
        return '';
    }

    function renderHighlights(highlights) {
        const el = document.getElementById('bc2-highlights');
        if (!el) return;
        if (!highlights.length) { el.innerHTML = ''; return; }
        const items = highlights.map(h => `<div class="bc2-hl">${escapeHtml(h)}</div>`).join('');
        el.innerHTML = `<div class="bc2-hl-title">Найденные рабочие стратегии</div>${items}`;
    }

    /* ───────── helpers ───────── */

    function formatElapsed(sec) {
        if (!sec || sec < 0) return '0с';
        const m = Math.floor(sec / 60), s = Math.round(sec % 60);
        return m > 0 ? `${m}м ${s}с` : `${s}с`;
    }
    function escapeHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { render, destroy, start, stop, clearOutput };
})();
