/**
 * blockcheck2_multi.js — вкладка «Несколько доменов» раздела
 * «Подбор стратегий».
 *
 * Клон штатного blockcheck2.sh с правками GUI (core/blockcheck2_patch):
 *   • домены (по одному на строку) проверяются ПАРАЛЛЕЛЬНО — копиями
 *     скрипта, до N одновременно; домены с общими IP — одной копией;
 *   • набрав N рабочих стратегий на тест (все попытки REPEATS успешны,
 *     при REPEATS=3 — 3/3), копия бросает оставшиеся варианты теста и
 *     идёт дальше;
 *   • по находкам собирается общая стратегия: профили через --new по
 *     доменам и семействам (HTTP/TLS/QUIC) — минимальным набором, по
 *     домену, своим выбором или всеми сочетаниями.
 *
 * API: /api/blockcheck2m/{start,status,output,stop,combine}.
 */

const Blockcheck2MultiPage = (() => {
    let pollTimer = null;
    let scriptFound = false;
    let lastStatus = null;
    let selDomain = '';           // чей вывод показан в терминале
    let outOffset = 0;
    let combo = null;             // последний ответ /combine
    let formState = null;

    const TEXT_IDS = ['bcm-domains', 'bcm-concurrency', 'bcm-stop-after', 'bcm-repeats',
        'bcm-scanlevel', 'bcm-ipvs', 'bcm-mode', 'bcm-limit', 'bcm-env'];
    const CHECK_IDS = ['bcm-http', 'bcm-tls12', 'bcm-tls13', 'bcm-http3', 'bcm-https-get',
        'bcm-skip-ipblock', 'bcm-skip-dnscheck', 'bcm-pause', 'bcm-group-ips', 'bcm-partial'];

    /* ───────── lifecycle ───────── */

    function render(container) {
        container.innerHTML = `
            <div class="card">
                <div id="bcm-script-info" style="font-size:13px;color:var(--text-muted);">Поиск скрипта…</div>
                <div style="font-size:12px;color:var(--text-muted);margin-top:6px;line-height:1.5;">
                    Тот же <code>blockcheck2.sh</code>, что на вкладке «Официальный», — клонированный
                    с правками: домены проверяются параллельно, а набрав нужное число рабочих
                    стратегий, проверка переходит к следующему тесту или домену. В конце из находок
                    собирается одна стратегия на все домены (профили через <code>--new</code>).
                </div>
            </div>

            <div class="card">
                <div class="card-title">Параметры</div>
                <div class="bc-form">
                    <div class="form-group">
                        <label class="form-label">Домены
                            <span style="font-weight:normal;color:var(--text-muted);font-size:11px;margin-left:6px;">(по одному на строку)</span>
                        </label>
                        <textarea class="form-input" id="bcm-domains" rows="5"
                                  placeholder="rutracker.org&#10;youtube.com&#10;discord.com"
                                  style="font-family:var(--font-mono);font-size:12px;resize:vertical;line-height:1.6;"></textarea>
                    </div>

                    <div class="bc2-grid">
                        <div class="form-group">
                            <label class="form-label" title="Сколько копий blockcheck2 работают одновременно. 1 — домены по очереди. На слабом роутере больше 2 не ставьте: каждая копия гоняет curl и nfqws2.">Одновременно доменов</label>
                            <select class="form-select" id="bcm-concurrency">
                                <option value="1">1 (по очереди)</option>
                                <option value="2" selected>2</option>
                                <option value="3">3</option>
                                <option value="4">4</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label" title="Набрав столько рабочих стратегий на тест (все попытки успешны), blockcheck2 бросает оставшиеся варианты этого теста. 0 — перебрать всё, как оригинал.">Хватит рабочих на тест</label>
                            <select class="form-select" id="bcm-stop-after">
                                <option value="0">все (без остановки)</option>
                                <option value="1">1</option>
                                <option value="3" selected>3</option>
                                <option value="4">4</option>
                                <option value="5">5</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label" title="REPEATS: столько попыток на стратегию; рабочая — успешны все. 3 → успешность 3/3.">Попыток (REPEATS)</label>
                            <input class="form-input" id="bcm-repeats" type="number" min="1" max="10" value="3">
                        </div>
                        <div class="form-group">
                            <label class="form-label">SCANLEVEL</label>
                            <select class="form-select" id="bcm-scanlevel">
                                <option value="quick">quick</option>
                                <option value="standard" selected>standard</option>
                                <option value="force">force</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">IP-версия</label>
                            <select class="form-select" id="bcm-ipvs">
                                <option value="4" selected>IPv4</option>
                                <option value="6">IPv6</option>
                                <option value="46">IPv4 + IPv6</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Протоколы</label>
                        <div class="bc2-checks">
                            <label class="bc2-check"><input type="checkbox" id="bcm-http"> HTTP</label>
                            <label class="bc2-check"><input type="checkbox" id="bcm-tls12"> HTTPS TLS 1.2</label>
                            <label class="bc2-check"><input type="checkbox" id="bcm-tls13" checked> HTTPS TLS 1.3</label>
                            <label class="bc2-check"><input type="checkbox" id="bcm-http3"> HTTP/3 (QUIC)</label>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Дополнительно</label>
                        <div class="bc2-checks">
                            <label class="bc2-check" title="Пока идёт проверка, обход GUI (nfqws2 и правила перехвата) снят, после — возвращается как было. Иначе проверка шла бы поверх уже работающей стратегии.">
                                <input type="checkbox" id="bcm-pause" checked> Снять обход на время проверки</label>
                            <label class="bc2-check" title="Перехват blockcheck2 матчит по IP: две копии на одном адресе делили бы трафик. Такие домены проверяются одной копией по очереди.">
                                <input type="checkbox" id="bcm-group-ips" checked> Домены с общими IP — одной копией</label>
                            <label class="bc2-check" title="CURL_HTTPS_GET=1 — качать тело (GET), а не заголовки: ловит обрыв на ~16-20 КБ.">
                                <input type="checkbox" id="bcm-https-get"> Качать полное тело</label>
                            <label class="bc2-check" title="SKIP_IPBLOCK=1 — пропустить проверку блокировки по IP (быстрее).">
                                <input type="checkbox" id="bcm-skip-ipblock" checked> SKIP_IPBLOCK</label>
                            <label class="bc2-check" title="SKIP_DNSCHECK=1 — пропустить проверку подмены DNS (в каждой копии она одна и та же).">
                                <input type="checkbox" id="bcm-skip-dnscheck"> SKIP_DNSCHECK</label>
                        </div>
                    </div>

                    <details id="bcm-advanced">
                        <summary style="cursor:pointer;font-size:13px;color:var(--text-secondary);">Доп. переменные окружения blockcheck2</summary>
                        <div class="form-group" style="margin-top:10px;">
                            <textarea class="form-input" id="bcm-env" rows="3"
                                      placeholder="CURL_MAX_TIME=3&#10;MIN_TTL=2"
                                      style="font-family:var(--font-mono);font-size:12px;resize:vertical;"></textarea>
                            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">KEY=VALUE по одной на строку — как в шапке blockcheck2.sh. DOMAINS, BATCH и GUI_STOP_AFTER задаёт вкладка.</div>
                        </div>
                    </details>

                    <div class="bc-actions">
                        <button class="btn btn-primary" id="bcm-btn-start" onclick="Blockcheck2MultiPage.start()">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            Запустить
                        </button>
                        <button class="btn btn-ghost btn-sm hidden" id="bcm-btn-stop" onclick="Blockcheck2MultiPage.stop()">Остановить</button>
                        <span id="bcm-run-status" style="font-size:12px;color:var(--text-muted);margin-left:auto;"></span>
                    </div>
                </div>
            </div>

            <div class="card" id="bcm-progress-card">
                <div class="card-title">Ход проверки</div>
                <div id="bcm-jobs" style="font-size:13px;color:var(--text-muted);">Ещё не запускалась.</div>
            </div>

            <div class="card">
                <div class="card-title">Найденные стратегии</div>
                <div class="bc2-found" id="bcm-found"></div>
                <div id="bcm-found-empty" style="font-size:13px;color:var(--text-muted);">Пока ничего.</div>
            </div>

            <div class="card" id="bcm-combine-card">
                <div class="card-title">Общая стратегия для всех доменов</div>
                <div style="font-size:12px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;">
                    Профили собираются по семействам (HTTP · TLS 1.2/1.3 · QUIC) с фильтром из типа
                    теста и <code>--hostlist-domains</code>; профили склеиваются через <code>--new</code>.
                    Для TLS первыми идут приёмы, прошедшие и TLS 1.2, и TLS 1.3.
                </div>
                <div class="bc2-grid">
                    <div class="form-group">
                        <label class="form-label">Как собирать</label>
                        <select class="form-select" id="bcm-mode" onchange="Blockcheck2MultiPage.onModeChange()">
                            <option value="grouped" selected>Минимум профилей (общие приёмы)</option>
                            <option value="per_domain">Свой профиль каждому домену</option>
                            <option value="custom">Выбрать приём вручную</option>
                            <option value="all">Все сочетания (варианты)</option>
                        </select>
                    </div>
                    <div class="form-group" id="bcm-limit-group" style="display:none;">
                        <label class="form-label">Вариантов не больше</label>
                        <input class="form-input" id="bcm-limit" type="number" min="1" max="100" value="20">
                    </div>
                </div>
                <div class="bc2-checks" style="margin-bottom:10px;">
                    <label class="bc2-check" title="Брать и приёмы, прошедшие не все попытки (напр. 2/3).">
                        <input type="checkbox" id="bcm-partial"> Учитывать частично успешные</label>
                </div>
                <div id="bcm-custom"></div>
                <div class="bc-actions">
                    <button class="btn btn-primary" id="bcm-btn-combine" onclick="Blockcheck2MultiPage.combine()">Собрать стратегию</button>
                </div>
                <div id="bcm-variants" style="margin-top:12px;"></div>
            </div>

            <div class="card">
                <div class="card-title" style="display:flex;align-items:center;gap:10px;">
                    <span>Вывод blockcheck2</span>
                    <select class="form-select" id="bcm-out-domain" style="max-width:280px;font-size:12px;"
                            onchange="Blockcheck2MultiPage.selectDomain(this.value)"></select>
                </div>
                <pre class="bc2-term" id="bcm-term"></pre>
            </div>
        `;
        restoreForm();
        onModeChange();
        loadScript();
        fetchStatus(true);
        if (combo) renderCombo();
    }

    function destroy() {
        captureForm();
        stopPolling();
    }

    function captureForm() {
        const st = {};
        TEXT_IDS.forEach(id => { const e = document.getElementById(id); if (e) st[id] = e.value; });
        CHECK_IDS.forEach(id => { const e = document.getElementById(id); if (e) st[id] = e.checked; });
        formState = st;
    }
    function restoreForm() {
        if (!formState) return;
        TEXT_IDS.forEach(id => { const e = document.getElementById(id); if (e && formState[id] != null) e.value = formState[id]; });
        CHECK_IDS.forEach(id => { const e = document.getElementById(id); if (e && formState[id] != null) e.checked = formState[id]; });
    }

    async function loadScript() {
        const el = document.getElementById('bcm-script-info');
        try {
            const d = await API.get('/api/blockcheck2/script');
            scriptFound = !!(d && d.found);
            if (!el) return;
            el.innerHTML = scriptFound
                ? `Оригинал: <code style="color:var(--text-secondary);">${esc(d.script)}</code>`
                : `<span style="color:var(--warning,#fbbf24);">⚠ Скрипт blockcheck2 не найден.</span> `
                  + `Установите zapret2 или задайте <code>zapret.blockcheck2_path</code>.`;
            const btn = document.getElementById('bcm-btn-start');
            if (btn) btn.disabled = !scriptFound;
        } catch (e) { if (el) el.textContent = 'Ошибка: ' + e.message; }
    }

    /* ───────── run ───────── */

    function _chk(id) { const e = document.getElementById(id); return !!(e && e.checked); }
    function _val(id) { const e = document.getElementById(id); return e ? e.value : ''; }

    async function start() {
        const domains = _val('bcm-domains').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        if (!domains.length) { Toast.error('Укажите домены, по одному на строку'); return; }
        if (!(_chk('bcm-http') || _chk('bcm-tls12') || _chk('bcm-tls13') || _chk('bcm-http3'))) {
            Toast.error('Отметьте хотя бы один протокол'); return;
        }
        const params = {
            IPVS: _val('bcm-ipvs') || '4',
            REPEATS: String(Math.max(1, parseInt(_val('bcm-repeats'), 10) || 3)),
            ENABLE_HTTP: _chk('bcm-http') ? '1' : '0',
            ENABLE_HTTPS_TLS12: _chk('bcm-tls12') ? '1' : '0',
            ENABLE_HTTPS_TLS13: _chk('bcm-tls13') ? '1' : '0',
            ENABLE_HTTP3: _chk('bcm-http3') ? '1' : '0',
        };
        if (_chk('bcm-https-get')) params.CURL_HTTPS_GET = '1';
        if (_chk('bcm-skip-ipblock')) params.SKIP_IPBLOCK = '1';
        if (_chk('bcm-skip-dnscheck')) params.SKIP_DNSCHECK = '1';
        _val('bcm-env').split(/\r?\n/).forEach(line => {
            const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
            if (m) params[m[1].toUpperCase()] = m[2].trim();
        });
        try {
            const r = await API.post('/api/blockcheck2m/start', {
                domains, params,
                scanlevel: _val('bcm-scanlevel'),
                concurrency: parseInt(_val('bcm-concurrency'), 10) || 2,
                stop_after: parseInt(_val('bcm-stop-after'), 10) || 0,
                pause_bypass: _chk('bcm-pause'),
                group_shared_ips: _chk('bcm-group-ips'),
            });
            if (!r.ok) { Toast.error(r.error || 'Ошибка запуска'); return; }
            Toast.success('Проверка запущена: доменов ' + r.domains.length);
            combo = null;
            const v = document.getElementById('bcm-variants'); if (v) v.innerHTML = '';
            selDomain = r.domains[0] || '';
            outOffset = 0;
            const term = document.getElementById('bcm-term'); if (term) term.textContent = '';
            startPolling();
        } catch (e) { Toast.error(e.message); }
    }

    async function stop() {
        try { await API.post('/api/blockcheck2m/stop', {}); Toast.info('Остановка запрошена'); }
        catch (e) { Toast.error(e.message); }
    }

    function startPolling() { if (!pollTimer) pollTimer = setInterval(tick, 1200); tick(); }
    function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
    async function tick() { await fetchStatus(false); await fetchOutput(); }

    async function fetchStatus(initial) {
        try {
            const s = await API.get('/api/blockcheck2m/status');
            lastStatus = s;
            const running = !!s.running;
            const bs = document.getElementById('bcm-btn-start');
            const bt = document.getElementById('bcm-btn-stop');
            if (bs) bs.disabled = running || !scriptFound;
            if (bt) bt.classList.toggle('hidden', !running);
            const st = document.getElementById('bcm-run-status');
            if (st) {
                const fullN = (s.found || []).filter(f => f.full).length;
                st.textContent = s.started
                    ? (running ? '⏳ идёт' : '✓ завершено') + ` · ${fmtTime(s.elapsed_seconds)} · рабочих ${fullN}`
                      + (s.bypass_paused ? ' · обход снят' : '')
                    : '';
            }
            renderJobs(s);
            renderFound(s.found || []);
            renderDomainSelect(s);
            if (initial && running) startPolling();
            if (!running && pollTimer) { await fetchOutput(); stopPolling(); }
        } catch { /* тихо */ }
    }

    async function fetchOutput() {
        if (!selDomain) return;
        try {
            const d = await API.get('/api/blockcheck2m/output?domain=' + encodeURIComponent(selDomain)
                + '&offset=' + outOffset);
            if (d && d.lines && d.lines.length) appendLines(d.lines);
            if (d && typeof d.next_offset === 'number') outOffset = d.next_offset;
        } catch { /* тихо */ }
    }

    function selectDomain(dom) {
        selDomain = dom || '';
        outOffset = 0;
        const term = document.getElementById('bcm-term'); if (term) term.textContent = '';
        fetchOutput();
    }

    function appendLines(lines) {
        const term = document.getElementById('bcm-term');
        if (!term) return;
        const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
        const frag = document.createDocumentFragment();
        lines.forEach(line => {
            const span = document.createElement('span');
            span.className = /working strategy found|zapret-gui:/i.test(line) ? 'ln-hl'
                : (/UNAVAILABLE|FAIL|error/i.test(line) ? 'ln-bad'
                : (/\bAVAILABLE\b|SUCCESS/.test(line) ? 'ln-ok' : ''));
            span.textContent = line + '\n';
            frag.appendChild(span);
        });
        term.appendChild(frag);
        if (atBottom) term.scrollTop = term.scrollHeight;
    }

    /* ───────── render ───────── */

    const STATE_TEXT = { pending: 'в очереди', running: 'идёт', done: 'готово',
        error: 'ошибка', stopped: 'остановлено' };

    function renderJobs(s) {
        const el = document.getElementById('bcm-jobs');
        if (!el) return;
        if (!s.jobs || !s.jobs.length) {
            el.innerHTML = s.error ? `<span class="text-error">${esc(s.error)}</span>`
                : (s.running ? 'Подготовка (резолв доменов)…' : 'Ещё не запускалась.');
            return;
        }
        const rows = s.jobs.map(j => {
            const tests = (j.tests || []).map(t =>
                `<span title="${esc(t.test)} ipv${t.ipv} ${esc(t.domain)}: проверено ${t.tried}`
                + (t.skipped ? ' — набран лимит, остальное пропущено' : '') + `">`
                + `${esc(shortTest(t.test))}·${esc(t.domain)} ${t.tried}${t.skipped ? ' ✂' : ''}</span>`).join(' · ');
            const color = j.state === 'done' ? 'var(--success,#34d399)'
                : (j.state === 'error' ? 'var(--danger,#f87171)' : 'var(--text-secondary)');
            return `<tr>
                <td style="font-family:var(--font-mono);">${esc(j.domains.join(', '))}</td>
                <td style="color:${color};white-space:nowrap;">${STATE_TEXT[j.state] || j.state}${j.exit_code != null && j.state === 'error' ? ' (код ' + j.exit_code + ')' : ''}</td>
                <td style="white-space:nowrap;">${j.found_full}${j.found_total > j.found_full ? ' <span title="частично успешные" style="color:var(--warning,#fbbf24);">+' + (j.found_total - j.found_full) + '</span>' : ''}</td>
                <td style="font-size:11px;">${tests || esc(j.current || '')}</td>
                <td style="white-space:nowrap;">${fmtTime(j.elapsed_seconds)}</td>
            </tr>`;
        }).join('');
        el.innerHTML = `<div class="table-wrap"><table class="table" style="width:100%;font-size:12px;">
            <thead><tr><th>Домены (копия)</th><th>Статус</th><th>Рабочих</th><th>Тесты (проверено вариантов)</th><th>Время</th></tr></thead>
            <tbody>${rows}</tbody></table></div>`
            + (s.error ? `<div class="text-error" style="margin-top:6px;">${esc(s.error)}</div>` : '');
    }

    function shortTest(t) {
        t = String(t || '').toLowerCase();
        if (t.includes('http3')) return 'QUIC';
        if (t.includes('tls13')) return 'TLS1.3';
        if (t.includes('tls12')) return 'TLS1.2';
        return 'HTTP';
    }

    function renderFound(found) {
        const el = document.getElementById('bcm-found');
        const empty = document.getElementById('bcm-found-empty');
        if (!el) return;
        if (empty) empty.style.display = found.length ? 'none' : '';
        if (!found.length) { el.innerHTML = ''; return; }
        const byDom = {};
        found.forEach((f, i) => { (byDom[f.domain] = byDom[f.domain] || []).push({ f, i }); });
        el.innerHTML = Object.keys(byDom).map(dom => {
            const items = byDom[dom].sort((a, b) => (b.f.full - a.f.full));
            const chips = items.map(({ f, i }) => {
                const rate = `${f.ok}/${f.total}`;
                return `<button class="bc2-found-chip${f.full ? '' : ' bc2-found-partial'}" `
                    + `onclick="Blockcheck2MultiPage.useOne(${i})" title="Создать стратегию из этого приёма&#10;${esc(f.strategy)}">`
                    + `<span class="bc2-found-proto">${esc(f.label)}</span> `
                    + `<span class="bc2-found-rate">${rate}</span> `
                    + `<span class="bc2-found-strat">${esc(f.strategy.slice(0, 70))}</span></button>`;
            }).join('');
            return `<div style="margin-bottom:8px;"><div class="bc2-found-title"><span>${esc(dom)}</span></div>`
                + `<div class="bc2-found-chips">${chips}</div></div>`;
        }).join('');
    }

    function renderDomainSelect(s) {
        const sel = document.getElementById('bcm-out-domain');
        if (!sel) return;
        const doms = [];
        (s.jobs || []).forEach(j => j.domains.forEach(d => doms.push(d)));
        const html = doms.map(d => `<option value="${esc(d)}"${d === selDomain ? ' selected' : ''}>${esc(d)}</option>`).join('');
        if (sel.dataset.sig !== doms.join(',')) {
            sel.innerHTML = html;
            sel.dataset.sig = doms.join(',');
        }
        if (!selDomain && doms.length) { selDomain = doms[0]; fetchOutput(); }
    }

    /* ───────── strategies ───────── */

    function useOne(i) {
        const f = ((lastStatus && lastStatus.found) || [])[i];
        if (!f || typeof StrategiesPage === 'undefined') return;
        const fam = f.l7 === 'quic' ? 'quic' : (f.l7 === 'http' ? 'http' : 'tls');
        const args = `--filter-${f.proto}=${f.port} --filter-l7=${f.l7} --hostlist-domains=${f.domain} `
            + (/--payload=/.test(f.strategy) ? '' : `--payload=${f.payload} `) + f.strategy;
        StrategiesPage.prefillCreate({
            name: `${f.domain} · ${f.label} ${f.ok}/${f.total} (blockcheck2)`,
            description: `Найдено blockcheck2 (несколько доменов), ${fam}, успех ${f.ok}/${f.total}`,
            args: args.trim(),
        });
    }

    function onModeChange() {
        const mode = _val('bcm-mode');
        const lg = document.getElementById('bcm-limit-group');
        if (lg) lg.style.display = mode === 'all' ? '' : 'none';
        renderCustom();
    }

    // Выбор приёма руками: по паре домен × семейство — список кандидатов
    // из последней сборки (или найденных).
    function renderCustom() {
        const box = document.getElementById('bcm-custom');
        if (!box) return;
        if (_val('bcm-mode') !== 'custom' || !combo || !combo.candidates) { box.innerHTML = ''; return; }
        box.innerHTML = `<div class="table-wrap"><table class="table" style="width:100%;font-size:12px;margin-bottom:10px;">
            <thead><tr><th>Домен</th><th>Трафик</th><th>Приём</th></tr></thead><tbody>`
            + combo.candidates.map((c, k) => `<tr><td style="font-family:var(--font-mono);">${esc(c.domain)}</td>`
                + `<td>${esc(c.label)}</td><td><select class="form-select bcm-choice" data-key="${esc(c.domain + '|' + c.family)}" `
                + `style="font-family:var(--font-mono);font-size:11px;">`
                + c.strategies.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')
                + `</select></td></tr>`).join('')
            + `</tbody></table></div>`;
    }

    async function combine() {
        const mode = _val('bcm-mode');
        const body = { mode, include_partial: _chk('bcm-partial'),
            limit: parseInt(_val('bcm-limit'), 10) || 20 };
        if (mode === 'custom') {
            const choices = {};
            document.querySelectorAll('.bcm-choice').forEach(el => { choices[el.dataset.key] = el.value; });
            body.choices = choices;
        }
        try {
            const r = await API.post('/api/blockcheck2m/combine', body);
            if (!r.ok) { Toast.error(r.error || 'Не собралось'); return; }
            const hadCustom = !!(combo && combo.candidates);
            combo = r;
            renderCombo();
            if (mode === 'custom' && !hadCustom) {
                renderCustom();
                Toast.info('Выберите приёмы и нажмите «Собрать» ещё раз');
            }
        } catch (e) { Toast.error(e.message); }
    }

    function renderCombo() {
        const box = document.getElementById('bcm-variants');
        if (!box || !combo) return;
        const n = combo.variants.length;
        const head = combo.mode === 'all'
            ? `<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Сочетаний всего: ${combo.total_combinations}; `
              + `уникальных показано: ${n}${combo.truncated ? ' (обрезано лимитом)' : ''}. `
              + `<button class="btn btn-ghost btn-sm" onclick="Blockcheck2MultiPage.saveAll()">Сохранить все ${n} как стратегии</button></div>`
            : '';
        box.innerHTML = head + combo.variants.map((v, i) => {
            const prof = v.profiles.map(p => `<li><b>${esc(p.label)}</b> · ${esc(p.domains.join(', '))}: `
                + `<code style="font-size:11px;">${esc(p.strategy)}</code></li>`).join('');
            return `<div style="border:1px solid var(--border,#2a2f3a);border-radius:8px;padding:10px;margin-bottom:10px;">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
                    <b>${n > 1 ? 'Вариант ' + (i + 1) : 'Стратегия'}</b>
                    <span style="font-size:12px;color:var(--text-muted);">профилей: ${v.profiles.length}</span>
                    <span style="margin-left:auto;display:flex;gap:6px;">
                        <button class="btn btn-ghost btn-sm" onclick="Blockcheck2MultiPage.copyVariant(${i})">Копировать</button>
                        <button class="btn btn-primary btn-sm" onclick="Blockcheck2MultiPage.createVariant(${i})">Создать стратегию</button>
                    </span>
                </div>
                <ul style="margin:0 0 6px 18px;font-size:12px;">${prof}</ul>
                <pre class="bc2-term" style="max-height:160px;">${esc(v.args)}</pre>
            </div>`;
        }).join('');
    }

    function _variantPayload(i) {
        const v = combo && combo.variants[i];
        if (!v) return null;
        const doms = [];
        v.profiles.forEach(p => p.domains.forEach(d => { if (doms.indexOf(d) < 0) doms.push(d); }));
        const title = doms.length > 3 ? doms.slice(0, 3).join(', ') + ` и ещё ${doms.length - 3}` : doms.join(', ');
        const profiles = v.profiles.map((p, k) => ({
            id: `bc2m${k + 1}`, name: `${p.label} · ${p.domains.join(', ')}`.slice(0, 80), enabled: true,
            // Глобальные декларации (--blob/--lua-init) — в первый профиль,
            // до первого --new.
            args: (k === 0 && v.globals.length ? v.globals.join(' ') + ' ' : '') + p.args,
        }));
        return {
            name: `blockcheck2: ${title}` + (combo.variants.length > 1 ? ` (вариант ${i + 1})` : ''),
            description: `Собрано из находок blockcheck2 (несколько доменов), режим ${combo.mode}: `
                + v.profiles.map(p => `${p.label} ${p.domains.join(',')}`).join('; '),
            profiles, args: v.args,
        };
    }

    function createVariant(i) {
        const p = _variantPayload(i);
        if (!p || typeof StrategiesPage === 'undefined') return;
        StrategiesPage.prefillCreate(p);
    }

    function copyVariant(i) {
        const p = _variantPayload(i);
        if (p) Clipboard.copyWithToast(p.args, { okText: 'Стратегия скопирована' });
    }

    async function saveAll() {
        if (!combo || !combo.variants.length) return;
        const stamp = Date.now().toString(36);
        let ok = 0;
        for (let i = 0; i < combo.variants.length; i++) {
            const p = _variantPayload(i);
            try {
                const r = await API.post('/api/strategies', {
                    id: `bc2m_${stamp}_${i + 1}`, name: p.name, description: p.description,
                    type: 'combined', profiles: p.profiles,
                });
                if (r && r.ok) ok++;
            } catch { /* дальше */ }
        }
        Toast.success(`Сохранено стратегий: ${ok} из ${combo.variants.length} — они в «Мои стратегии»`);
    }

    /* ───────── helpers ───────── */

    function fmtTime(sec) {
        if (!sec || sec < 0) return '0с';
        const m = Math.floor(sec / 60), s = Math.round(sec % 60);
        return m > 0 ? `${m}м ${s}с` : `${s}с`;
    }
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { render, destroy, start, stop, selectDomain, useOne, onModeChange,
        combine, createVariant, copyVariant, saveAll };
})();
