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
    let foundStrategies = [];     // структурные находки для кликабельных бейджей
    let foundKeys = new Set();    // дедуп бейджей (ipv|test|domain|strategy)
    let bcCur = null;             // текущий разбираемый блок стратегии
    let formState = null;         // сохранённые значения формы (домены, галки) между переключениями вкладок

    // Поля формы, состояние которых переживает уход/возврат на вкладку (SKILL-task §8).
    const FORM_TEXT_IDS = ['bc2-domains', 'bc2-scanlevel', 'bc2-ipvs', 'bc2-repeats', 'bc2-env', 'bc2-args'];
    const FORM_CHECK_IDS = ['bc2-http', 'bc2-tls12', 'bc2-tls13', 'bc2-http3', 'bc2-https-get',
        'bc2-skip-pktws', 'bc2-skip-ipblock', 'bc2-skip-dnscheck', 'bc2-parallel', 'bc2-curl-verbose'];

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
                <div class="bc2-found" id="bc2-found"></div>
                <div class="bc2-highlights" id="bc2-highlights"></div>
                <pre class="bc2-term" id="bc2-term"></pre>
            </div>
        `;

        // Восстанавливаем заполненные ранее домены/галки (форма пересоздаётся
        // при каждом render, а бейджи живут в module-state — SKILL-task §8).
        restoreFormState();

        loadScript();
        // Подтянуть текущее состояние (вдруг запуск уже идёт).
        outOffset = 0;
        fetchStatus(true);
    }

    function destroy() {
        // Сохраняем значения формы перед уничтожением DOM, чтобы при возврате
        // на вкладку домены и галки не потерялись.
        captureFormState();
        stopPolling();
    }

    /* ───────── сохранение/восстановление формы ───────── */

    function captureFormState() {
        const st = {};
        let any = false;
        FORM_TEXT_IDS.forEach(id => {
            const e = document.getElementById(id);
            if (e) { st[id] = e.value; any = true; }
        });
        FORM_CHECK_IDS.forEach(id => {
            const e = document.getElementById(id);
            if (e) { st[id] = e.checked; any = true; }
        });
        const adv = document.getElementById('bc2-advanced');
        if (adv) { st._adv = adv.open; any = true; }
        if (any) formState = st;
    }

    function restoreFormState() {
        if (!formState) return;
        FORM_TEXT_IDS.forEach(id => {
            const e = document.getElementById(id);
            if (e && formState[id] != null) e.value = formState[id];
        });
        FORM_CHECK_IDS.forEach(id => {
            const e = document.getElementById(id);
            if (e && formState[id] != null) e.checked = formState[id];
        });
        const adv = document.getElementById('bc2-advanced');
        if (adv && formState._adv != null) adv.open = formState._adv;
    }

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
        foundStrategies = [];
        foundKeys = new Set();
        bcCur = null;
        const fnd = document.getElementById('bc2-found');
        if (fnd) fnd.innerHTML = '';
    }

    /* ───────── polling ───────── */

    function startPolling() {
        if (!pollTimer) pollTimer = setInterval(tick, 800);
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
            // Бейджи ведём из потокового лога (см. processScanLine). Здесь
            // лишь перерисовываем накопленное — чтобы они не пропали при
            // возврате на вкладку и переотрисовке DOM.
            renderFoundChips();

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
        let foundChanged = false;
        lines.forEach(line => {
            const span = document.createElement('span');
            span.className = lineClass(line);
            span.textContent = line + '\n';
            frag.appendChild(span);
            // Разбор потокового лога blockcheck2 по «блокам стратегии», чтобы
            // бейдж со стратегией и успешностью (напр. 3/3) появлялся СРАЗУ
            // при завершении проверки очередной стратегии, не дожидаясь
            // итоговой сводки «working strategy found» (она печатается только
            // в конце прогона).
            if (processScanLine(line)) foundChanged = true;
        });
        term.appendChild(frag);
        if (atBottom) term.scrollTop = term.scrollHeight;
        if (foundChanged) renderFoundChips();
    }

    function classifyTest(test) {
        const t = String(test || '').toLowerCase();
        if (t.includes('http3') || t.includes('quic'))
            return { proto: 'udp', port: '443', l7: 'quic', payload: 'quic_initial', label: 'QUIC' };
        if (t.includes('tls13'))
            return { proto: 'tcp', port: '443', l7: 'tls', payload: 'tls_client_hello', label: 'TLS1.3' };
        if (t.includes('tls12'))
            return { proto: 'tcp', port: '443', l7: 'tls', payload: 'tls_client_hello', label: 'TLS1.2' };
        if (t.includes('https') || t.includes('tls'))
            return { proto: 'tcp', port: '443', l7: 'tls', payload: 'tls_client_hello', label: 'HTTPS' };
        return { proto: 'tcp', port: '80', l7: 'http', payload: 'http_req', label: 'HTTP' };
    }

    // Анонс проверяемой стратегии:
    //   - curl_test_https_tls12 ipv4 youtube.com : nfqws2 --payload=… --lua-desync=…
    const ANNOUNCE_RE = /^-\s+(\S+)\s+ipv([46])\s+(\S+)\s*:\s*(\S+)\s+(--.+)$/;
    // Маркер попытки в начале строки: [attempt N] …
    const ATTEMPT_RE = /^\[attempt\s+(\d+)\]/i;

    // Признак «попытка удалась»: строка содержит AVAILABLE, но это не итог
    // «!!!!! AVAILABLE !!!!!» и не UNAVAILABLE.
    function isAttemptSuccess(line) {
        return /\bAVAILABLE\b/.test(line) && !/UNAVAILABLE/.test(line)
            && !line.includes('!!!!!');
    }

    // Обработать одну строку лога. Возвращает true, если добавлен новый бейдж.
    function processScanLine(line) {
        const s = String(line || '');

        // 1) Новый блок стратегии. Сначала финализируем предыдущий (если без
        // явного вердикта — по факту накопленных попыток).
        const a = s.match(ANNOUNCE_RE);
        if (a) {
            const added = finalizeBlock();
            const info = classifyTest(a[1]);
            bcCur = {
                test: a[1], ipv: parseInt(a[2], 10), domain: a[3],
                engine: a[4], strategy: a[5].trim(),
                proto: info.proto, port: info.port, l7: info.l7,
                payload: info.payload, label: info.label,
                attemptMax: 0, okCount: 0, full: false,
            };
            return added;
        }

        if (!bcCur) return false;

        // 2) Маркер попытки — обновляем число попыток.
        const at = s.match(ATTEMPT_RE);
        if (at) {
            const n = parseInt(at[1], 10);
            if (n > bcCur.attemptMax) bcCur.attemptMax = n;
        }
        // 3) Успех попытки (в т.ч. «[attempt N] AVAILABLE» и одиночное AVAILABLE).
        if (isAttemptSuccess(s)) bcCur.okCount += 1;

        // 4) Вердикт блока.
        if (/!!!!!\s*AVAILABLE\s*!!!!!/.test(s)) {
            bcCur.full = true;
            return finalizeBlock();
        }
        if (/^UNAVAILABLE\b/.test(s.trim())) {
            return finalizeBlock();
        }
        return false;
    }

    // Завершить текущий блок: посчитать ok/total и при ok>0 — добавить бейдж.
    function finalizeBlock() {
        const b = bcCur;
        bcCur = null;
        if (!b) return false;
        const total = b.attemptMax > 0 ? b.attemptMax : 1;
        let ok = b.okCount;
        // REPEATS=1: попыток в выводе нет (нет «[attempt]»/«AVAILABLE»), судим
        // по вердикту.
        if (b.attemptMax === 0) ok = b.full ? 1 : 0;
        if (ok <= 0 && !b.full) return false;
        if (ok <= 0 && b.full) ok = total;
        return addFound({
            test: b.test, ipv: b.ipv, domain: b.domain, engine: b.engine,
            strategy: b.strategy, proto: b.proto, port: b.port, l7: b.l7,
            payload: b.payload, label: b.label,
            ok: ok, total: total, full: !!b.full,
        });
    }

    function foundKey(f) {
        return [f.ipv, f.test, f.domain, f.strategy].join('|');
    }

    // Добавить находку с дедупом. true — если добавлена новая.
    function addFound(f) {
        if (!f) return false;
        const k = foundKey(f);
        if (foundKeys.has(k)) return false;
        foundKeys.add(k);
        foundStrategies.push(f);
        return true;
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

    // Кликабельные бейджи: каждый показывает стратегию + успешность (ok/total)
    // и открывает редактор создания стратегии, предзаполненный этим приёмом
    // (фильтр из типа теста + дословный --payload/--lua-desync, SKILL §3).
    // Полностью успешные (вердикт «!!!!! AVAILABLE !!!!!», напр. 3/3) — вверху
    // и зелёные; частичные (напр. 2/3) — ниже и янтарные.
    // Порядок бейджей: сначала полностью успешные, затем по убыванию ok/total.
    // Общий для отрисовки чипов и «копировать все» (task §2).
    function _foundOrder() {
        return foundStrategies
            .map((f, i) => ({ f, i }))
            .sort((a, b) => {
                if (!!b.f.full - !!a.f.full) return (b.f.full ? 1 : 0) - (a.f.full ? 1 : 0);
                const ra = (a.f.ok || 0) / (a.f.total || 1);
                const rb = (b.f.ok || 0) / (b.f.total || 1);
                return rb - ra;
            });
    }

    // Реконструкция дословных args приёма: фильтр (из типа теста) + опционально
    // --hostlist-domains=<домены> + payload (если нет в стратегии) + сама стратегия.
    function _buildArgs(f, domains) {
        const strat = String(f.strategy || '');
        let args = `--filter-${f.proto}=${f.port} --filter-l7=${f.l7} `;
        if (domains && domains.length && !/--hostlist-domains=/.test(strat)) {
            args += `--hostlist-domains=${domains.join(',')} `;
        }
        if (!/--payload=/.test(strat) && f.payload) {
            args += `--payload=${f.payload} `;
        }
        args += strat;
        return args.trim();
    }

    // Домены из поля формы (по одному на строку) — для --hostlist-domains (task §1).
    function _domainsFromForm() {
        const t = (document.getElementById('bc2-domains') || {}).value || '';
        return t.split('\n').map(s => s.trim()).filter(Boolean);
    }

    function renderFoundChips() {
        const el = document.getElementById('bc2-found');
        if (!el) return;
        if (!foundStrategies.length) { el.innerHTML = ''; return; }

        // Индексы в исходном массиве сохраняем для useStrategy(i).
        const order = _foundOrder();

        const chips = order.map(({ f, i }) => {
            const rate = (f.ok != null && f.total != null) ? (f.ok + '/' + f.total) : '';
            const cls = 'bc2-found-chip' + (f.full ? '' : ' bc2-found-partial');
            const ttl = escapeHtml(`${f.engine || 'nfqws2'} ${f.strategy || ''}`.slice(0, 240));
            return `<button class="${cls}" onclick="Blockcheck2Page.useStrategy(${i})" `
                + `title="Создать стратегию из этого приёма&#10;успех ${rate}&#10;${ttl}">`
                + `<span class="bc2-found-proto">${escapeHtml(f.label || '')}</span> `
                + `<span class="bc2-found-dom">${escapeHtml(f.domain || '')}</span> `
                + (rate ? `<span class="bc2-found-rate">${escapeHtml(rate)}</span> ` : '')
                + `<span class="bc2-found-strat">${escapeHtml((f.strategy || '').slice(0, 60))}</span>`
                + `<span class="bc2-found-arrow">→ создать</span></button>`;
        }).join('');
        const full = foundStrategies.filter(f => f.full).length;
        el.innerHTML = `<div class="bc2-found-title">`
            + `<span>Рабочие стратегии blockcheck2 `
            + `(${full} полных · ${foundStrategies.length} всего · клик — создать)</span>`
            + `<button class="btn btn-ghost btn-sm bc2-found-copy" onclick="Blockcheck2Page.copyAllFound()" `
            + `title="Скопировать все найденные стратегии в буфер обмена — потом сами скомпонуете нужные через --new">`
            + `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13" style="margin-right:4px;">`
            + `<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>`
            + `<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`
            + `Копировать все</button></div>`
            + `<div class="bc2-found-chips">${chips}</div>`;
    }

    // Копировать список всех найденных стратегий в буфер обмена (task §2).
    // Каждый приём — комментарий с доменом/успехом + готовая строка args,
    // чтобы пользователь сам скомпоновал нужные профили через --new.
    // Домены для --hostlist-domains подставляем из поля формы; если пусто —
    // используем сам протестированный домен (как в useStrategy, чтобы
    // «Копировать все» и клик по бейджу давали одинаковую сборку).
    function copyAllFound() {
        if (!foundStrategies.length) { Toast && Toast.info && Toast.info('Пока нет найденных стратегий'); return; }
        const formDomains = _domainsFromForm();
        const lines = [`# Рабочие стратегии blockcheck2 (${foundStrategies.length})`, ''];
        _foundOrder().forEach(({ f }) => {
            const rate = (f.ok != null && f.total != null) ? `${f.ok}/${f.total}` : '';
            const domList = formDomains.length ? formDomains : (f.domain ? [f.domain] : []);
            lines.push(`# ${f.label || ''} · ${f.domain || ''}`
                + (rate ? ` · успех ${rate}` : '') + (f.full ? '' : ' (не все попытки)'));
            lines.push(`${f.engine || 'nfqws2'} ${_buildArgs(f, domList)}`);
            lines.push('');
        });
        _copyText(lines.join('\n').trim() + '\n', `Скопировано стратегий: ${foundStrategies.length}`);
    }

    // Копирование в буфер с fallback на execCommand (как в strategies.js).
    function _copyText(text, okMsg) {
        const done = () => Toast && Toast.success && Toast.success(okMsg || 'Скопировано');
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(() => _copyFallback(text, done));
        } else {
            _copyFallback(text, done);
        }
    }
    function _copyFallback(text, done) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            done();
        } catch (_e) {
            Toast && Toast.error && Toast.error('Не удалось скопировать');
        }
    }

    function useStrategy(index) {
        const f = foundStrategies[index];
        if (!f) return;
        if (typeof StrategiesPage === 'undefined' || !StrategiesPage.prefillCreate) {
            Toast && Toast.error && Toast.error('Страница стратегий недоступна');
            return;
        }
        // Домены для --hostlist-domains берём из поля формы; если пусто —
        // используем сам протестированный домен (task §1).
        const formDomains = _domainsFromForm();
        const domList = formDomains.length ? formDomains : (f.domain ? [f.domain] : []);
        const args = _buildArgs(f, domList);
        const rate = (f.ok != null && f.total != null) ? ` ${f.ok}/${f.total}` : '';
        StrategiesPage.prefillCreate({
            name: `${f.domain} · ${f.label}${rate} (blockcheck2)`,
            description: `Найдено blockcheck2 для ipv${f.ipv} ${f.domain}`
                + (rate ? ` · успех${rate}` + (f.full ? '' : ' (не все попытки)') : ''),
            args: args,
        });
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

    return { render, destroy, start, stop, clearOutput, useStrategy, copyAllFound };
})();
