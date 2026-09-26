/**
 * scan.js — Страница подбора стратегий (Strategy Scanner).
 *
 * Для человека, а не для отладчика: что проверяем и чем, на каком шаге
 * подбор, что нашлось и почему остальное не подошло — словами, а не
 * кодами ошибок. Тонкости (параметры стратегии, коды) — по раскрытию.
 *
 * Сервер: /api/scan/{start,status,results,stop,apply/<idx>}.
 */

const ScanPage = (() => {
    /* ───────── state ───────── */
    let pollTimer = null;
    let lastStatus = null;

    // Быстрый выбор цели: домен + протокол, который для неё обычно нужен.
    // Хостинги — одна цель на всех: блокировка по сети провайдера рвёт
    // загрузку у всех сайтов на его адресах, стратегия подбирается без
    // привязки к доменам (профиль hosting в core/scan_targets.py).
    const QUICK_TARGETS = [
        { label: 'YouTube',   target: 'youtube.com',   protocol: 'tcp' },
        { label: 'YouTube (QUIC)', target: 'youtube.com', protocol: 'udp' },
        { label: 'X / Twitter', target: 'x.com',       protocol: 'tcp' },
        { label: 'Facebook',  target: 'facebook.com',  protocol: 'tcp' },
        { label: 'Instagram', target: 'instagram.com', protocol: 'tcp' },
        { label: 'Cloudflare 1.1.1.1', target: 'one.one.one.one', protocol: 'tcp' },
        { label: 'Хостинги (Hetzner, OVH, DO, Linode)', target: 'hel1-speed.hetzner.com', protocol: 'tcp' },
        { label: 'Discord',   target: 'discord.com',   protocol: 'tcp' },
        { label: 'Telegram',  target: 'web.telegram.org', protocol: 'tcp' },
    ];

    // Цели, которые проверяются по сети провайдера, а не по домену.
    const HOSTING_HINTS = ['hetzner', 'ovh', 'digitalocean', 'linode'];

    // Домены, для которых UDP проверяется STUN (голос), а не QUIC.
    const STUN_HINTS = ['discord'];

    // Этапы прогона — в том порядке, в каком их проходит сервер.
    const STAGES = [
        { id: 'prepare',  label: 'Подготовка' },
        { id: 'baseline', label: 'Без обхода' },
        { id: 'scan',     label: 'Перебор' },
        { id: 'confirm',  label: 'Перепроверка' },
        { id: 'done',     label: 'Готово' },
    ];

    // Коды неудач → человеческие причины.
    const REASONS = {
        TCP_16_20:     'обрыв после 16–20 КБ — DPI режет загрузку',
        TLS_RESET:     'соединение сброшено (RST от DPI)',
        TCP_RESET:     'соединение сброшено (RST)',
        READ_RESET:    'соединение сброшено во время загрузки',
        RST:           'соединение сброшено',
        TLS_TIMEOUT:   'нет ответа при установке соединения',
        TCP_TIMEOUT:   'нет ответа',
        READ_TIMEOUT:  'загрузка зависла',
        TIMEOUT:       'нет ответа',
        TLS_EOF_EARLY: 'соединение оборвалось сразу',
        FAKE_LEAK:     'сервер получил фейковый пакет — стратегия не подходит',
        ISP_PAGE:      'открылась заглушка провайдера',
        HTTP_INJECT:   'провайдер подменил ответ',
        SHORT_BODY:    'пришло слишком мало данных',
        QUIC_TIMEOUT:  'QUIC не отвечает',
        QUIC_REFUSED:  'сервер не принимает QUIC',
        UNSTABLE:      'сработала случайно — при перепроверке нет',
        BASELINE_OPEN: 'сайт открывается и без обхода',
        NFQWS_FAIL:    'движок не запустился с этой стратегией',
        NFQWS_CRASHED: 'движок упал с этой стратегией',
        FW_FAIL:       'не удалось поставить правила firewall',
        NO_ARGS:       'пустая стратегия',
    };

    /* ───────── lifecycle ───────── */

    function render(container) {
        const chips = QUICK_TARGETS.map((t, i) =>
            `<button type="button" class="btn-chip" onclick="ScanPage.pickTarget(${i})">${escapeHtml(t.label)}</button>`
        ).join('');

        container.innerHTML = `
            <div class="page-container">
                <!-- Заголовок и вкладки рисует StrategyScanHubPage: эта
                     страница — вкладка «По каталогу zapret-gui». -->

                <div class="card" id="scan-controls">
                    <div class="card-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                        Что подбираем
                    </div>

                    <div class="bc-form">
                        <div class="form-group">
                            <label class="form-label" for="scan-target">Сайт, который не открывается</label>
                            <input class="form-input" id="scan-target" type="text"
                                   placeholder="youtube.com" value="youtube.com"
                                   spellcheck="false" autocomplete="off"
                                   oninput="ScanPage.refreshHints()"
                                   style="font-family:var(--font-mono); font-size:13px;">
                            <div class="scan-quick-targets">${chips}</div>
                        </div>

                        <div class="bc-form-row">
                            <div class="form-group" style="flex:1; min-width:220px;">
                                <label class="form-label" for="scan-protocol">Что не работает</label>
                                <select class="form-select" id="scan-protocol" onchange="ScanPage.refreshHints()">
                                    <option value="tcp" selected>Сайт или видео не грузится (TCP)</option>
                                    <option value="udp">QUIC / HTTP3 или голос (UDP)</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1; min-width:220px;">
                                <label class="form-label" for="scan-mode">Сколько стратегий пробовать</label>
                                <select class="form-select" id="scan-mode">
                                    <option value="quick" selected>Быстро — около 30, несколько минут</option>
                                    <option value="standard">Больше — около 80 и сгенерированные</option>
                                    <option value="full">Все — долго, для трудных случаев</option>
                                </select>
                            </div>
                        </div>

                        <div class="bc-form-row">
                            <div class="form-group" style="flex:1; min-width:220px;">
                                <label class="form-label" for="scan-stop-after">Когда остановиться</label>
                                <select class="form-select" id="scan-stop-after">
                                    <option value="1">Как только найдётся рабочая</option>
                                    <option value="3" selected>Когда найдутся 3 рабочие</option>
                                    <option value="5">Когда найдутся 5 рабочих</option>
                                    <option value="0">Проверить все</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:1; min-width:220px; justify-content:flex-end;">
                                <label class="checkbox-option" style="margin-top:22px;">
                                    <input type="checkbox" id="scan-confirm" checked>
                                    Перепроверить лучшие несколько раз (надёжнее)
                                </label>
                            </div>
                        </div>

                        <div class="scan-note" id="scan-probe-hint"></div>

                        <div class="bc-actions" id="scan-actions">
                            <button class="btn btn-primary" id="scan-btn-start" onclick="ScanPage.start(false)">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polygon points="5 3 19 12 5 21 5 3"/>
                                </svg>
                                Подобрать стратегию
                            </button>
                            <button class="btn btn-ghost btn-sm hidden" id="scan-btn-resume" onclick="ScanPage.start(true)">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                                </svg>
                                <span id="scan-btn-resume-label">Продолжить</span>
                            </button>
                            <button class="btn btn-ghost btn-sm hidden" id="scan-btn-stop" onclick="ScanPage.stop()" style="color:var(--error);">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="6" y="6" width="12" height="12" rx="1"/>
                                </svg>
                                Остановить
                            </button>
                        </div>

                        <details class="scan-howto">
                            <summary>Как проходит подбор</summary>
                            <ol>
                                <li><b>Без обхода.</b> Сначала проверяем, правда ли сайт заблокирован. Если он открывается и так — подбирать нечего.</li>
                                <li><b>Перебор.</b> По очереди запускаем обход с каждой стратегией и проверяем сайт по-настоящему: для TCP скачиваем 64 КБ (многие блокировки пропускают первые 16–20 КБ и рвут связь), для QUIC отправляем такое же приветствие с именем сайта, как браузер.</li>
                                <li><b>Перепроверка.</b> Лучшие находки проверяем ещё пару раз: один удачный замер бывает случайностью.</li>
                                <li><b>Память.</b> Что сработало, запоминается для вашей сети — в следующий раз эти стратегии проверим первыми.</li>
                            </ol>
                            <p>На время подбора обход останавливается, потом всё возвращается как было.</p>
                        </details>
                    </div>
                </div>

                <div class="card hidden" id="scan-progress-card">
                    <div class="card-title">Ход подбора</div>
                    <div class="scan-stepper" id="scan-stepper"></div>
                    <div class="bc-progress-info" style="margin-top:12px;">
                        <span class="bc-phase" id="scan-phase"></span>
                        <span class="bc-elapsed" id="scan-elapsed-time"></span>
                    </div>
                    <div class="diag-progress" style="margin-top:8px;">
                        <div class="diag-progress-track">
                            <div class="diag-progress-bar" id="scan-progress-bar" style="width:0%"></div>
                        </div>
                        <span class="diag-progress-text" id="scan-progress-text"></span>
                    </div>
                    <div id="scan-current-strategy" class="scan-current"></div>
                    <div class="scan-counters">
                        <span style="color:var(--success);" id="scan-working-count"></span>
                        <span style="color:var(--text-muted);" id="scan-failed-count"></span>
                    </div>
                    <div id="scan-notes"></div>
                </div>

                <div class="hidden" id="scan-results-section">
                    <div class="card">
                        <div class="card-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            Результат
                        </div>
                        <div id="scan-verdict"></div>
                        <div id="scan-results-list" style="margin-top:12px;"></div>
                        <div id="scan-failures"></div>
                    </div>
                </div>
            </div>
        `;

        refreshHints();
        fetchStatus();
    }

    function destroy() {
        stopPolling();
        lastStatus = null;
    }

    /* ───────── controls ───────── */

    function pickTarget(i) {
        const t = QUICK_TARGETS[i];
        if (!t) return;
        const target = document.getElementById('scan-target');
        const proto = document.getElementById('scan-protocol');
        if (target && !target.disabled) target.value = t.target;
        if (proto && !proto.disabled) proto.value = t.protocol;
        refreshHints();
    }

    /** Подсказка «чем будем проверять» — под выбранные цель и протокол. */
    function refreshHints() {
        const el = document.getElementById('scan-probe-hint');
        if (!el) return;
        const target = (document.getElementById('scan-target')?.value || '').trim().toLowerCase();
        const proto = document.getElementById('scan-protocol')?.value || 'tcp';
        let text;
        if (proto === 'udp') {
            const stun = STUN_HINTS.some(h => target.split('.').some(l => l.startsWith(h)));
            text = stun
                ? 'Проверка: STUN-запрос по UDP — так работает голосовая связь. Для голоса Discord подбирайте UDP, для самого сайта — TCP.'
                : 'Проверка: QUIC-рукопожатие с именем сайта, как у браузера (HTTP/3). Если сайт открывается, но видео тормозит — часто дело в QUIC.';
        } else if (HOSTING_HINTS.some(h => target.split('.').some(l => l.startsWith(h)))) {
            text = 'Проверка: скачиваем 64 КБ со speedtest-серверов Hetzner, OVH, DigitalOcean и Linode. Блокировка хостингов обычно обрывает загрузку на 16–20 КБ у всех сайтов на их адресах — поэтому стратегия подбирается для всего трафика, без списка доменов.';
        } else {
            text = 'Проверка: скачиваем 64 КБ с сайта. Блокировки часто пропускают первые 16–20 КБ и обрывают — такая стратегия не засчитывается.';
        }
        el.textContent = text;
    }

    /* ───────── API ───────── */

    async function start(resume) {
        const target = (document.getElementById('scan-target')?.value || '').trim();
        if (!target) {
            Toast.error('Укажите сайт, для которого подобрать стратегию');
            return;
        }

        const body = {
            target,
            protocol: document.getElementById('scan-protocol')?.value || 'tcp',
            mode: document.getElementById('scan-mode')?.value || 'quick',
            stop_after: parseInt(document.getElementById('scan-stop-after')?.value || '0', 10) || 0,
            confirm: !!document.getElementById('scan-confirm')?.checked,
        };
        if (resume) body.resume = true;

        try {
            const res = await API.post('/api/scan/start', body);
            if (res.ok) {
                Toast.success(resume ? 'Продолжаем подбор' : 'Подбор запущен — это займёт несколько минут');
                const section = document.getElementById('scan-results-section');
                if (section) section.classList.add('hidden');
                startPolling();
                fetchStatus();
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function stop() {
        try {
            await API.post('/api/scan/stop', {});
            Toast.info('Останавливаем — текущая проверка доработает и обход вернётся как был');
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function applyStrategy(idx) {
        try {
            const res = await API.post('/api/scan/apply/' + idx, {});
            if (res.ok) {
                Toast.success('Стратегия применена и сохранена в «Мои стратегии». Автозапуск тоже её помнит.');
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
                if (data.status === 'completed' || data.status === 'cancelled' || data.status === 'error') {
                    await fetchResults();
                }
            }
        } catch {
            // тихо: следующий опрос попробует снова
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
        const canResume = data.status === 'cancelled'
            || (data.status === 'completed' && data.stopped_early);

        const btnStart = document.getElementById('scan-btn-start');
        const btnStop = document.getElementById('scan-btn-stop');
        const btnResume = document.getElementById('scan-btn-resume');
        if (btnStart) {
            btnStart.disabled = isRunning;
            btnStart.classList.toggle('btn-disabled', isRunning);
        }
        if (btnStop) btnStop.classList.toggle('hidden', !isRunning);
        if (btnResume) btnResume.classList.toggle('hidden', !canResume);
        setElText('scan-btn-resume-label',
                  data.stopped_early ? 'Искать дальше' : 'Продолжить с места остановки');

        ['scan-target', 'scan-protocol', 'scan-mode', 'scan-stop-after', 'scan-confirm'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = isRunning;
        });

        // Поля — из статуса сервера: вернувшись на страницу во время или
        // после подбора, человек видит реальную цель, а не youtube.com.
        if (!isIdle) {
            setValue('scan-target', data.target);
            setValue('scan-protocol', data.protocol);
            setValue('scan-mode', data.mode);
            if (data.stop_after !== undefined) setValue('scan-stop-after', String(data.stop_after));
            const confirm = document.getElementById('scan-confirm');
            if (confirm && data.confirm !== undefined) confirm.checked = !!data.confirm;
            refreshHints();
        }

        const progressCard = document.getElementById('scan-progress-card');
        if (progressCard) progressCard.classList.toggle('hidden', isIdle);
        if (isIdle) return;

        renderStepper(data);

        const stage = data.stage || (isRunning ? 'prepare' : 'done');
        let pct = 0;
        let counter = '';
        if (stage === 'confirm' && data.confirm_total > 0) {
            pct = Math.round((data.confirm_progress / data.confirm_total) * 100);
            counter = data.confirm_progress + ' / ' + data.confirm_total + ' перепроверок';
        } else if (data.total > 0) {
            pct = Math.round((data.progress / data.total) * 100);
            counter = data.progress + ' / ' + data.total + ' стратегий';
        }
        if (!isRunning) pct = 100;
        const bar = document.getElementById('scan-progress-bar');
        if (bar) {
            bar.style.width = pct + '%';
            bar.style.background = (data.status === 'completed' && data.working_count > 0)
                ? 'var(--success)' : '';
        }
        setElText('scan-progress-text', counter);

        setElText('scan-phase', phaseText(data));
        setElText('scan-current-strategy',
                  isRunning && data.current_strategy ? 'Сейчас: ' + data.current_strategy : '');
        setElText('scan-working-count', 'Рабочих: ' + (data.working_count || 0)
                  + (data.confirmed_count ? ' (подтверждено: ' + data.confirmed_count + ')' : ''));
        setElText('scan-failed-count', 'Не подошло: ' + (data.failed_count || 0));
        setElText('scan-elapsed-time', data.elapsed_seconds > 0 ? formatElapsed(data.elapsed_seconds) : '');

        renderNotes(data);
    }

    function phaseText(data) {
        if (data.status === 'error') return 'Подбор прервался: ' + (data.error || 'неизвестная ошибка');
        if (data.status === 'cancelled') return 'Остановлено — обход вернулся в прежнее состояние';
        if (data.status === 'completed') {
            if (data.stopped_early) return 'Готово: найдено достаточно рабочих стратегий';
            return 'Готово';
        }
        const stage = data.stage;
        if (stage === 'baseline') return 'Проверяем, заблокирован ли сайт без обхода…';
        if (stage === 'scan') return 'Пробуем стратегии по очереди…';
        if (stage === 'confirm') return 'Перепроверяем лучшие находки…';
        return data.phase || 'Готовимся…';
    }

    function renderStepper(data) {
        const el = document.getElementById('scan-stepper');
        if (!el) return;
        const visible = STAGES.filter(s => s.id !== 'confirm' || data.confirm !== false);
        const current = data.status === 'running' ? (data.stage || 'prepare') : 'done';
        const idx = visible.findIndex(s => s.id === current);
        el.innerHTML = visible.map((s, i) => {
            let cls = 'scan-step';
            if (i < idx || (current === 'done' && data.status === 'completed')) cls += ' done';
            else if (i === idx) cls += ' active';
            return `<span class="${cls}"><span class="scan-step-dot">${i + 1}</span>${escapeHtml(s.label)}</span>`;
        }).join('<span class="scan-step-sep"></span>');
    }

    function renderNotes(data) {
        const notes = [];
        if (data.baseline_open) {
            const all = data.baseline_by_af && Object.values(data.baseline_by_af).every(Boolean);
            notes.push(all
                ? ['warn', 'Сайт открывается и без обхода — подбирать нечего. Если он всё же не работает в браузере, попробуйте другой протокол (TCP/UDP) или другой адрес сайта.']
                : ['info', 'Без обхода сайт открывается только частично (' + openFamilies(data.baseline_by_af) + ') — стратегии проверяем там, где он закрыт.']);
        }
        if (data.memory_first > 0) {
            const one = data.memory_first === 1;
            const what = plural(data.memory_first, 'стратегию', 'стратегии', 'стратегий')
                + (one ? ', которая уже помогала' : ', которые уже помогали') + ' в вашей сети.';
            notes.push(['info', (data.status === 'running' ? 'Сначала проверяем ' : 'Первыми проверили ') + what]);
        }
        if (data.rules_reapplied > 0) {
            notes.push(['warn', 'Системный firewall ' + plural(data.rules_reapplied, 'раз', 'раза', 'раз')
                + ' сбросил наши правила посреди подбора — мы их вернули. Если результаты странные, повторите подбор.']);
        }
        const el = document.getElementById('scan-notes');
        if (!el) return;
        el.innerHTML = notes.map(([kind, text]) =>
            `<div class="scan-note scan-note-${kind}">${escapeHtml(text)}</div>`).join('');
    }

    /* ───────── Results ───────── */

    function renderResults(working, report) {
        const section = document.getElementById('scan-results-section');
        if (section) section.classList.remove('hidden');
        renderVerdict(working, report);
        renderWorking(working, report);
        renderFailures(report);
    }

    function renderVerdict(working, report) {
        const el = document.getElementById('scan-verdict');
        if (!el) return;
        const r = report || {};
        const chips = [];
        if (r.total_tested) chips.push(['muted', 'Проверено: ' + r.total_tested]);
        if (r.elapsed_seconds) chips.push(['muted', 'Время: ' + formatElapsed(r.elapsed_seconds)]);
        if (r.confirmed_count) chips.push(['ok', 'Подтверждено перепроверкой: ' + r.confirmed_count]);
        if (r.memory_first) chips.push(['muted', 'Из памяти первыми: ' + r.memory_first]);

        let cls, icon, title, detail;
        if (working.length) {
            const best = r.best_strategy || working[0];
            cls = 'v-ok'; icon = '✅';
            title = 'Найдено ' + plural(working.length, 'рабочая стратегия', 'рабочие стратегии', 'рабочих стратегий');
            detail = 'Лучшая — «' + (best.strategy_name || best.strategy_id) + '». Нажмите «Применить» — обход запустится с ней и останется после перезагрузки.';
            if (r.stopped_early) detail += ' Перебор остановлен досрочно — можно «Искать дальше».';
        } else if (r.baseline_accessible && !(r.failed_strategies || []).some(f => f.error !== 'BASELINE_OPEN')) {
            cls = 'v-skip'; icon = 'ℹ️';
            title = 'Сайт открывается и без обхода';
            detail = 'Стратегия тут не нужна. Если в браузере он всё равно не работает — попробуйте подбор по другому протоколу.';
        } else if (r.cancelled) {
            cls = 'v-warn'; icon = '⏸';
            title = 'Подбор остановлен, рабочих пока нет';
            detail = 'Можно продолжить с места остановки.';
        } else {
            cls = 'v-bad'; icon = '❌';
            title = 'Рабочих стратегий не нашлось';
            detail = hintForNothing(r);
        }
        el.innerHTML = `
            <div class="bc-verdict ${cls}">
                <div class="bc-verdict-icon">${icon}</div>
                <div class="bc-verdict-body">
                    <div class="bc-verdict-title">${escapeHtml(title)}</div>
                    <div class="bc-verdict-detail">${escapeHtml(detail)}</div>
                    <div class="bc-verdict-chips">${chips.map(([k, t]) =>
                        `<span class="bc-chip bc-chip-${k}">${escapeHtml(t)}</span>`).join('')}</div>
                </div>
            </div>`;
    }

    function hintForNothing(r) {
        const tips = [];
        if (r.mode === 'quick') tips.push('запустите подбор в режиме «Больше» или «Все»');
        if (r.protocol === 'tcp') tips.push('если сайт открывается, но видео тормозит — попробуйте UDP (QUIC)');
        tips.push('если не помогает ничего — вероятна блокировка по IP, тогда нужен туннель (AWG/WARP), а не стратегия');
        return 'Что можно сделать: ' + tips.join('; ') + '.';
    }

    function renderWorking(working, report) {
        const el = document.getElementById('scan-results-list');
        if (!el) return;
        if (!working.length) { el.innerHTML = ''; return; }
        const kind = (report && report.probe_kind) || 'tls+body';
        const bestId = report && report.best_strategy && report.best_strategy.strategy_id;

        // Порядок — серверный (рабочие, подтверждённые, score): индекс
        // кнопки «Применить» обязан совпадать с серверным.
        el.innerHTML = working.map((w, i) => {
            const raw = w.raw_data || {};
            const name = escapeHtml(w.strategy_name || w.strategy_id || 'Стратегия #' + (i + 1));
            const badges = [];
            if (w.strategy_id === bestId) badges.push('<span class="bc-badge bc-badge-ok">Лучшая</span>');
            if (w.checks > 1) {
                badges.push(w.confirmed
                    ? `<span class="bc-badge bc-badge-ok" title="Прошла все проверки подряд">Проверена ${w.passes}/${w.checks}</span>`
                    : `<span class="bc-badge bc-badge-warn" title="Прошла не все перепроверки — может работать через раз">Прошла ${w.passes}/${w.checks}</span>`);
            }
            if (w.from_memory) badges.push('<span class="bc-badge" style="background:rgba(59,130,246,0.15); color:var(--accent);" title="Уже помогала на этом сайте в вашей сети">Уже работала у вас</span>');
            if (raw.is_full_preset) badges.push('<span class="bc-badge bc-badge-skip" title="Готовый набор со своими фильтрами">Готовый пресет</span>');
            if (raw.label === 'recommended') badges.push('<span class="bc-badge bc-badge-skip">Рекомендуемая</span>');

            const metrics = [];
            if (kind === 'tls+body') {
                if (w.throughput_kbps > 0) metrics.push('скорость ' + formatSpeed(w.throughput_kbps));
                if (w.latency_ms) metrics.push('загрузка за ' + Math.round(w.latency_ms) + ' мс');
            } else if (kind === 'quic') {
                metrics.push('QUIC отвечает' + (w.latency_ms ? ' за ' + Math.round(w.latency_ms) + ' мс' : ''));
            } else {
                metrics.push('STUN отвечает' + (w.latency_ms ? ' за ' + Math.round(w.latency_ms) + ' мс' : ''));
            }
            if (w.success_rate != null && w.success_rate < 1) {
                metrics.push('открылось на ' + Math.round(w.success_rate * 100) + '% проверенных адресов');
            }

            const args = escapeHtml(raw.args_preview || '');
            const origin = [raw.source_file, raw.level].filter(Boolean).join(' · ');
            return `
                <div class="scan-result-item">
                    <div class="scan-result-header">
                        <div class="scan-result-name">
                            <span class="bc-badge bc-badge-ok">#${i + 1}</span>
                            ${name} ${badges.join(' ')}
                        </div>
                        <div class="scan-result-meta">
                            <button class="btn btn-primary btn-sm" onclick="ScanPage.applyStrategy(${i})">Применить</button>
                        </div>
                    </div>
                    <div class="scan-result-metrics">${escapeHtml(metrics.join(' · '))}</div>
                    ${args ? `<details class="scan-result-details">
                        <summary>Параметры стратегии${origin ? ' (' + escapeHtml(origin) + ')' : ''}</summary>
                        <div class="scan-result-args">${args}</div>
                    </details>` : ''}
                </div>`;
        }).join('');
    }

    /** Почему остальное не подошло — сводка причин, самые частые сверху. */
    function renderFailures(report) {
        const el = document.getElementById('scan-failures');
        if (!el) return;
        const failed = (report && report.failed_strategies) || [];
        if (!failed.length) { el.innerHTML = ''; return; }
        const counts = {};
        failed.forEach(f => {
            const code = f.error || 'UNKNOWN';
            counts[code] = (counts[code] || 0) + 1;
        });
        const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([code, n]) =>
            `<li><span class="scan-reason-count">${n}</span> ${escapeHtml(REASONS[code] || 'другая причина')}
             <span class="scan-reason-code">${escapeHtml(code)}</span></li>`).join('');
        el.innerHTML = `
            <details class="scan-failures">
                <summary>Почему не подошли остальные (${failed.length})</summary>
                <ul>${rows}</ul>
            </details>`;
    }

    /* ───────── helpers ───────── */

    function openFamilies(map) {
        const open = Object.entries(map || {}).filter(([, ok]) => ok).map(([af]) => af === 'ipv6' ? 'IPv6' : 'IPv4');
        return open.length ? 'открыт по ' + open.join(', ') : '';
    }

    function plural(n, one, few, many) {
        const m10 = n % 10, m100 = n % 100;
        const word = (m10 === 1 && m100 !== 11) ? one
            : (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) ? few : many;
        return n + ' ' + word;
    }

    function formatSpeed(kbps) {
        return kbps >= 1024 ? (kbps / 1024).toFixed(1) + ' МБ/с' : Math.round(kbps) + ' КБ/с';
    }

    function setValue(id, value) {
        if (value === undefined || value === null || value === '') return;
        const el = document.getElementById(id);
        if (el) el.value = value;
    }

    function setElText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function escapeHtml(str) {
        if (str === undefined || str === null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function formatElapsed(seconds) {
        if (!seconds || seconds <= 0) return '';
        if (seconds < 60) return Math.round(seconds) + ' сек';
        const m = Math.floor(seconds / 60);
        const s = Math.round(seconds % 60);
        return m + ' мин ' + s + ' сек';
    }

    /* ───────── public ───────── */

    return { render, destroy, start, stop, applyStrategy, pickTarget, refreshHints };
})();
