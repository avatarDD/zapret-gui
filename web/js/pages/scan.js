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
    // Поля прерванного подбора с диска уже подставлены в форму.
    let _savedResumeApplied = false;

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
        _savedResumeApplied = false;
        const chips = QUICK_TARGETS.map((t, i) =>
            `<button type="button" class="btn-chip" onclick="ScanPage.pickTarget(${i})">${escapeHtml(t.label)}</button>`
        ).join('');

        container.innerHTML = `
            <div class="page-container">
                <!-- Заголовок и вкладки рисует StrategyScanHubPage: эта
                     страница — вкладка «nfqws2: по каталогу». -->

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
                                <select class="form-select" id="scan-mode" onchange="ScanPage.toggleCustom()">
                                    <option value="quick" selected>Быстро — около 30, несколько минут</option>
                                    <option value="standard">Больше — около 80 и сгенерированные</option>
                                    <option value="full">Все — долго, для трудных случаев</option>
                                    <option value="custom">Свою — вставить текст из чата</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-group hidden" id="scan-custom-group">
                            <label class="form-label" for="scan-custom">Своя стратегия</label>
                            <textarea class="form-input" id="scan-custom" rows="5" spellcheck="false"
                                      style="font-family:var(--font-mono); font-size:12px;"
                                      placeholder="Вставьте как есть: в кавычках, с подписью, целой командой nfqws2 или NFQWS2_OPT=…"></textarea>
                            <p class="form-hint">Каждая часть (через --new или пустую строку) — отдельный кандидат, до 10.
                                Берутся только шаги --lua-desync: порты и списки подбор ставит сам под ваш сайт.
                                Неизвестную функцию или блоб назовём до запуска.</p>
                            <button type="button" class="btn btn-ghost btn-sm" onclick="ScanPage.checkCustom()">Проверить текст</button>
                            <div id="scan-custom-check" style="margin-top:8px; font-size:13px;"></div>
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
                                <label class="checkbox-option" title="Несколько стратегий разом в песочнице — сколько выдержит память роутера (128 МБ — 5, 256 МБ — 10, больше — 15). Нужен nfqws2 1.0.5+. Находки перепроверяются по одной.">
                                    <input type="checkbox" id="scan-parallel">
                                    Проверять несколько разом (быстрее)
                                </label>
                                <label class="checkbox-option" title="До 8 стратегий, которые сработали у абонентов вашего провайдера (открытая база zemidala/nfqws2-strategies по номеру AS). Подбор узнает провайдера по внешнему адресу через RIPEstat и скачает базу с GitHub.">
                                    <input type="checkbox" id="scan-community">
                                    Сначала стратегии сообщества для моего провайдера
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

                <div class="card" id="scan-freeze">
                    <div class="card-title">Обрыв на 16 КБ по сетям хостингов</div>
                    <p class="form-hint">Провайдер может обрывать загрузку с адресов Hetzner, OVH, Cloudflare и других
                        хостингов на 16–20 КБ — у всех сайтов на них сразу. Проба проверит ~20 сетей без обхода, а где
                        обрыв есть — подберёт имя для фейка, которое его снимает (в песочнице, обход сети не трогается,
                        до 15 минут). Находки пойдут в подбор первыми, а «Применить для сети» поставит приём только на
                        адреса этой сети.</p>
                    <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                        <button type="button" class="btn btn-ghost btn-sm" id="scan-freeze-start" onclick="ScanPage.freezeStart()">Проверить сети</button>
                        <button type="button" class="btn btn-ghost btn-sm hidden" id="scan-freeze-stop" onclick="ScanPage.freezeStop()">Остановить</button>
                        <span id="scan-freeze-progress" style="font-size:13px; color:var(--text-muted);"></span>
                    </div>
                    <div id="scan-freeze-result" style="margin-top:8px; font-size:13px;"></div>
                </div>

                <div class="card" id="scan-community-card">
                    <div class="card-title">Стратегии сообщества</div>
                    <p class="form-hint">Открытая база стратегий по провайдерам (номер AS): что сработало у абонентов
                        вашего провайдера. Провайдер определяется по внешнему адресу через RIPEstat, база читается с GitHub.
                        Поделиться своей находкой — кнопкой у результата подбора: откроется заполненная форма, отправляете вы сами.</p>
                    <button type="button" class="btn btn-ghost btn-sm" onclick="ScanPage.communityLoad(false)">Показать для моего провайдера</button>
                    <button type="button" class="btn btn-ghost btn-sm" onclick="ScanPage.communityLoad(true)">Обновить</button>
                    <div id="scan-community-list" style="margin-top:8px; font-size:13px;"></div>
                </div>
            </div>
        `;

        refreshHints();
        fetchStatus();
        freezeFetch();
        initParallel();
    }

    /** Галка «несколько разом» — по настройке scan.parallel. */
    async function initParallel() {
        try {
            const data = await API.get('/api/config');
            const v = String((data && data.config && data.config.scan
                              && data.config.scan.parallel) || 'off').toLowerCase();
            const el = document.getElementById('scan-parallel');
            if (el && !el.disabled) el.checked = v === 'auto' || v === 'on' || parseInt(v, 10) > 1;
            const comm = document.getElementById('scan-community');
            if (comm && !comm.disabled) comm.checked = !!(data.config.scan && data.config.scan.community);
        } catch (_e) { /* без фатала */ }
    }

    function destroy() {
        stopPolling();
        freezeStopPolling();
        lastStatus = null;
    }

    /* ───────── проба «обрыв на 16 КБ» ───────── */

    let freezeTimer = null;

    function freezeStopPolling() {
        if (freezeTimer) clearInterval(freezeTimer);
        freezeTimer = null;
    }

    async function freezeFetch() {
        let s;
        try {
            s = await API.get('/api/scan/freeze');
        } catch (err) {
            return;
        }
        renderFreeze(s);
        const running = s.state === 'running';
        if (running && !freezeTimer) freezeTimer = setInterval(freezeFetch, 3000);
        if (!running) freezeStopPolling();
    }

    async function freezeStart() {
        try {
            const res = await API.post('/api/scan/freeze/start', {});
            if (res.ok) {
                Toast.success('Проба запущена');
                freezeFetch();
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function freezeStop() {
        try {
            await API.post('/api/scan/freeze/stop', {});
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function freezeApply(asn) {
        if (!confirm('Поставить найденный приём профилем на адреса AS' + asn
            + '? Текущая стратегия сохранится под ним, применение — с проверкой и откатом.')) return;
        try {
            const res = await API.post('/api/scan/freeze/apply', { asn: String(asn) });
            if (res.ok) {
                Toast.success('Применяем с проверкой: адресов в списке ' + res.ipset + ' — ' + res.prefixes);
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    const FREEZE_END = {
        stopped: 'остановлена', time: 'вышло время (15 минут)', error: 'ошибка',
    };

    function renderFreeze(s) {
        const prog = document.getElementById('scan-freeze-progress');
        const out = document.getElementById('scan-freeze-result');
        if (!prog || !out) return;
        const running = s.state === 'running';
        document.getElementById('scan-freeze-start')?.classList.toggle('hidden', running);
        document.getElementById('scan-freeze-stop')?.classList.toggle('hidden', !running);
        const nets = Array.isArray(s.nets) ? s.nets : [];
        if (running) {
            const phase = s.phase === 'names' ? 'подбор имени' : 'замер без обхода';
            prog.textContent = phase + ' · ' + (s.done || 0) + '/' + (s.total || 0)
                + (s.current ? ' · ' + s.current : '');
        } else if (s.state && s.state !== 'idle') {
            const when = s.finished ? new Date(s.finished * 1000).toLocaleString() : '';
            prog.textContent = 'Прошлая проба: ' + when
                + (FREEZE_END[s.state] ? ' · ' + FREEZE_END[s.state] : '')
                + (s.error ? ' · ' + s.error : '');
        } else {
            prog.textContent = '';
        }
        if (!nets.length) {
            out.innerHTML = '';
            return;
        }
        const frozen = nets.filter(n => n.verdict === 'freeze');
        const okCount = nets.filter(n => n.verdict === 'ok').length;
        const errCount = nets.filter(n => n.verdict === 'error').length;
        let html = '<div>Без обхода: открываются ' + okCount + ', обрыв — ' + frozen.length
            + (errCount ? ', не ответили — ' + errCount : '') + '.</div>';
        if (frozen.length) {
            html += '<table class="table" style="margin-top:6px;"><tbody>' + frozen.map(n => {
                const name = 'AS' + escapeHtml(n.asn) + ' ' + escapeHtml(n.provider);
                let what;
                if (n.found && !running) {
                    what = 'снимает: <code>' + escapeHtml(n.found.steps.join(' ')) + '</code> '
                        + '<button type="button" class="btn btn-primary btn-sm" onclick="ScanPage.freezeApply(\''
                        + escapeHtml(n.asn) + '\')">Применить для сети</button>';
                } else if (n.found) {
                    what = 'снимает: <code>' + escapeHtml(n.found.steps.join(' ')) + '</code>';
                } else if (running && s.phase === 'names') {
                    what = 'подбираем… (проверено ' + (n.tried || 0) + ')';
                } else {
                    what = 'ни одно имя не помогло' + (n.tried ? ' (проверено ' + n.tried + ')' : '');
                }
                return '<tr><td>' + name + '</td><td>' + what + '</td></tr>';
            }).join('') + '</tbody></table>';
        }
        out.innerHTML = html;
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
            parallel: !!document.getElementById('scan-parallel')?.checked,
            community: !!document.getElementById('scan-community')?.checked,
        };
        if (resume) body.resume = true;
        if (body.mode === 'custom') {
            body.custom = document.getElementById('scan-custom')?.value || '';
            if (!body.custom.trim()) {
                Toast.error('Вставьте свою стратегию в поле под списком');
                return;
            }
        }

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
            // Разбор не прошёл — показываем почему, по частям.
            if (body.custom && err.data) renderCustomCheck(err.data);
            Toast.error(err.message);
        }
    }

    async function refine(lighter) {
        try {
            const res = await API.post('/api/scan/refine', { lighter: !!lighter });
            if (res.ok) {
                Toast.success((lighter ? 'Ищем вариант полегче' : 'Уточняем')
                    + ' «' + res.base + '»: вариантов — ' + res.variants);
                const section = document.getElementById('scan-results-section');
                if (section) section.classList.add('hidden');
                startPolling();
                fetchStatus();
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function toggleCustom() {
        const custom = document.getElementById('scan-mode')?.value === 'custom';
        document.getElementById('scan-custom-group')?.classList.toggle('hidden', !custom);
    }

    async function checkCustom() {
        const text = document.getElementById('scan-custom')?.value || '';
        const protocol = document.getElementById('scan-protocol')?.value || 'tcp';
        try {
            renderCustomCheck(await API.post('/api/scan/custom/check', { text, protocol }));
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function renderCustomCheck(r) {
        const box = document.getElementById('scan-custom-check');
        if (!box || !r) return;
        const esc = escapeHtml;
        let html = '';
        (r.candidates || []).forEach((c, i) => {
            html += '<div style="color:var(--success);">✓ Кандидат ' + (i + 1) + ': <code>'
                + esc(c.args.join(' ')) + '</code></div>';
        });
        (r.rejected || []).forEach(x => {
            html += '<div style="color:var(--error);">✗ Часть ' + x.index + ': ' + esc(x.reason)
                + (x.args && x.args.length ? ' <code>' + esc(x.args.join(' ')) + '</code>' : '') + '</div>';
        });
        if (r.dropped) {
            html += '<div class="text-muted">Ещё ' + r.dropped + ' не вошли: больше 10 за раз не проверяем.</div>';
        }
        if (!html) html = '<div class="text-muted">' + esc(r.error || 'Ничего не нашлось') + '</div>';
        box.innerHTML = html;
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
        // Прерванный подбор с диска: после перезапуска GUI или роутера
        // статус сканера «idle», но позиция и найденное сохранены.
        const saved = (isIdle && data.saved_resume && data.saved_resume.next_index > 0)
            ? data.saved_resume : null;
        const canResume = !!saved || (data.mode !== 'custom' && (data.status === 'cancelled'
            || (data.status === 'completed' && data.stopped_early)));

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
                  saved ? `Продолжить прерванный подбор (${saved.target}, с ${saved.next_index + 1}-й, найдено ${saved.working_count})`
                        : (data.stopped_early ? 'Искать дальше' : 'Продолжить с места остановки'));
        // Поля прерванного прогона — один раз: «Продолжить» сверяет цель,
        // протокол и режим, а дальше человек вправе их поменять.
        if (saved && !_savedResumeApplied) {
            _savedResumeApplied = true;
            setValue('scan-target', saved.target);
            setValue('scan-protocol', saved.protocol);
            setValue('scan-mode', saved.mode);
            toggleCustom();
            refreshHints();
        }

        ['scan-target', 'scan-protocol', 'scan-mode', 'scan-stop-after', 'scan-confirm', 'scan-parallel', 'scan-community', 'scan-custom'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = isRunning;
        });

        // Поля — из статуса сервера: вернувшись на страницу во время или
        // после подбора, человек видит реальную цель, а не youtube.com.
        if (!isIdle) {
            setValue('scan-target', data.target);
            setValue('scan-protocol', data.protocol);
            setValue('scan-mode', data.mode);
            toggleCustom();
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
        // Песочница: кандидаты — во втором nfqws2, обход сети работает.
        if (data.status === 'running' && data.stage && data.stage !== 'prepare') {
            notes.push(data.isolated
                ? ['info', 'Кандидаты проверяются в отдельном экземпляре nfqws2 — обход для устройств сети работает как обычно.']
                : ['warn', 'Обход сети на время подбора остановлен'
                    + (data.isolation_note ? ' (' + data.isolation_note + ')' : '') + '.']);
        }
        if (data.community_first > 0) {
            notes.push(['info', (data.status === 'running' ? 'Сначала проверяем ' : 'Первыми проверили ')
                + plural(data.community_first, 'стратегию', 'стратегии', 'стратегий')
                + ' сообщества для вашего провайдера (AS' + ((data.community || {}).asn || '?') + ').']);
        } else if (data.community && data.community.error) {
            notes.push(['info', 'Стратегии сообщества не проверялись: ' + data.community.error + '.']);
        } else if (data.community && data.community.asn && data.status !== 'running') {
            notes.push(['info', 'Для вашего провайдера (AS' + data.community.asn + ') в базе сообщества стратегий пока нет — поделитесь найденной.']);
        }
        if (data.status === 'running' && data.parallel > 0) {
            notes.push(['info', 'Проверяем до ' + data.parallel + ' стратегий разом (по памяти роутера); находки перепроверяются по одной.']);
        } else if (data.status === 'running' && data.parallel_note) {
            notes.push(['info', 'Проверяем по одной: ' + data.parallel_note + '.']);
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
        // «Уточнение»: почти рабочую — параметрами фейка, рабочую — полегче.
        let refine = '';
        if (working.length) {
            const best = r.best_strategy || working[0];
            cls = 'v-ok'; icon = '✅';
            title = 'Найдено ' + plural(working.length, 'рабочая стратегия', 'рабочие стратегии', 'рабочих стратегий');
            detail = 'Лучшая — «' + (best.strategy_name || best.strategy_id) + '». Нажмите «Применить» — обход запустится с ней и останется после перезагрузки.';
            if (r.stopped_early) detail += ' Перебор остановлен досрочно — можно «Искать дальше».';
            refine = '<button class="btn btn-ghost btn-sm" onclick="ScanPage.refine(true)" '
                + 'title="Убрать лишние шаги и повторы у лучшей рабочей: меньше нагрузки, меньше поводов сломаться">'
                + 'Искать вариант полегче</button>';
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
            refine = '<button class="btn btn-primary btn-sm" onclick="ScanPage.refine(false)" '
                + 'title="Взять стратегию, продвинувшуюся дальше всех, и перебрать параметры её фейка: способ обмана DPI, повторы, подставное имя, настоящий ClientHello">'
                + 'Уточнить лучшую попытку</button>';
        }
        el.innerHTML = `
            <div class="bc-verdict ${cls}">
                <div class="bc-verdict-icon">${icon}</div>
                <div class="bc-verdict-body">
                    <div class="bc-verdict-title">${escapeHtml(title)}</div>
                    <div class="bc-verdict-detail">${escapeHtml(detail)}</div>
                    <div class="bc-verdict-chips">${chips.map(([k, t]) =>
                        `<span class="bc-chip bc-chip-${k}">${escapeHtml(t)}</span>`).join('')}</div>
                    ${refine ? '<div style="margin-top:8px;">' + refine + '</div>' : ''}
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

    let shareItems = [];

    function renderWorking(working, report) {
        const el = document.getElementById('scan-results-list');
        if (!el) return;
        shareItems = [];
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
            if (raw.label === 'community') badges.push('<span class="bc-badge" title="' + escapeHtml(w.description || 'Из базы сообщества') + '">Сообщество</span>');
            // Единственная маскировка — tcp_ts: с роутера работает, с Windows
            // нет (Windows не шлёт метки TCP). Подбор идёт с роутера и этого
            // не видит — предупреждаем здесь.
            if (typeof Nfqws2Lint !== 'undefined' && Nfqws2Lint.needsTcpTimestamps(raw.args_preview || '')) {
                badges.push('<span class="bc-badge bc-badge-warn" title="Фейк маскируется только через tcp_ts. Windows по умолчанию не шлёт метки TCP — включите: netsh interface tcp set global timestamps=enabled (от администратора)">Нужны метки TCP</span>');
            }

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
                            ${kind === 'tls+body' ? shareButton(w, true) : ''}
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
        // Из базы сообщества, но не сработала — можно отметить в базе.
        const comm = failed.filter(f => (f.raw_data || {}).label === 'community');
        const commRows = comm.map(f => `<li>${escapeHtml(f.strategy_name || f.strategy_id)} ${shareButton(f, false)}</li>`).join('');
        el.innerHTML = `
            ${comm.length ? `<div style="margin-top:8px;">Из базы сообщества у вас не сработали:<ul>${commRows}</ul></div>` : ''}
            <details class="scan-failures">
                <summary>Почему не подошли остальные (${failed.length})</summary>
                <ul>${rows}</ul>
            </details>`;
    }

    /* ───────── база сообщества ───────── */

    async function communityLoad(force) {
        const out = document.getElementById('scan-community-list');
        if (!out) return;
        out.textContent = 'Загружаем…';
        let d;
        try {
            d = await API.get('/api/scan/community?detect=1' + (force ? '&force=1' : ''));
        } catch (err) {
            out.textContent = err.message;
            return;
        }
        if (!d.asn) {
            out.textContent = d.error || 'Провайдер не определён — впишите номер AS в настройке community.asn.';
            return;
        }
        const head = 'AS' + escapeHtml(d.asn) + (d.provider ? ' · ' + escapeHtml(d.provider) : '')
            + (d.auto ? ' (определён по внешнему адресу; если это туннель, а не провайдер, впишите номер в community.asn)' : '')
            + ' — ' + plural(d.items.length, 'стратегия', 'стратегии', 'стратегий')
            + (d.error ? ' · ' + escapeHtml(d.error) : '');
        const rows = d.items.map(x => '<tr' + (x.skipped ? ' style="opacity:.55"' : '') + '><td><code>'
            + escapeHtml(x.steps.join(' ')) + '</code></td><td>подтвердили ' + x.reports
            + (x.fails ? ', не сработала у ' + x.fails : '') + '</td><td>' + escapeHtml(x.last || '—')
            + (x.fresh ? '' : ' (давно)') + (x.skipped ? ' · не пробуется' : '') + '</td></tr>').join('');
        out.innerHTML = '<div>' + head + ' · <a href="' + escapeHtml(d.page || d.repo)
            + '" target="_blank" rel="noopener">в репозитории</a></div>'
            + (rows ? '<table class="table" style="margin-top:6px;"><tbody>' + rows + '</tbody></table>'
                : '<div style="margin-top:4px;">Для вашего провайдера в базе пока ничего нет — поделитесь найденной в подборе.</div>');
    }

    /** «Поделиться» (своя находка), «Подтвердить» / «Не сработала» (из базы). */
    function shareButton(r, works) {
        const raw = r.raw_data || {};
        const fromBase = raw.label === 'community';
        if (!works && !fromBase) return '';
        const idx = shareItems.push({ r, works }) - 1;
        const [text, title] = !works
            ? ['Не сработала', 'Отметить в базе сообщества: роутеры будут пробовать её позже других']
            : fromBase
                ? ['Подтвердить', 'Сработала и у вас — подтвердите в базе, это поднимет её для других']
                : ['Поделиться', 'Отправить в базу сообщества: её будут пробовать абоненты вашего провайдера'];
        return `<button class="btn btn-ghost btn-sm" title="${escapeHtml(title)}" onclick="ScanPage.share(${idx})">${text}</button>`;
    }

    async function share(idx) {
        const item = shareItems[idx];
        if (!item) return;
        const r = item.r;
        const raw = r.raw_data || {};
        const src = String(raw.source_file || '');
        const body = {
            outcome: item.works ? 'works' : 'fails',
            args: raw.args_preview || '',
            host: (lastStatus && lastStatus.target) || '',
            community: src.startsWith('community:') ? src.slice(10) : '',
            result: r.checks > 1 ? r.passes + '/' + r.checks : (item.works ? '1/1' : '0/1'),
            proto: (lastStatus && lastStatus.family) === 'http' ? 'http' : 'tls',
        };
        try {
            const res = await API.post('/api/scan/community/share', body);
            if (!res.ok) return;
            if (!confirm('Откроется форма issue на GitHub — отправляете вы сами. В ней будет:\n\n' + res.text)) return;
            window.open(res.url, '_blank', 'noopener');
        } catch (err) {
            Toast.error(err.message);
        }
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

    return { render, destroy, start, stop, applyStrategy, pickTarget, refreshHints,
             toggleCustom, checkCustom, refine, freezeStart, freezeStop, freezeApply, share, communityLoad };
})();
