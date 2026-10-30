/**
 * geneva.js — «Движок обхода»: выбор nfqws2 / geneva_c и страница geneva.
 *
 * Что на странице, сверху вниз:
 *   1. Чем обходить блокировки — две плитки (nfqws2 и geneva_c): какой
 *      активен, работает ли, что у него сохранено. Переключение — с
 *      подтверждением: второй движок останавливается.
 *   2. Движок geneva — состояние, рабочая стратегия, счётчики пакетов,
 *      срабатывания деревьев и вердикт человеческим языком.
 *   3. Подбор стратегии — форма, прогресс по поколениям, лента событий,
 *      последние оценки и найденное с кнопкой «Сделать рабочей».
 *      Прерванный подбор продолжается с сохранённого места.
 *   4. Библиотека Geneva — готовые стратегии из статьи: проверить на
 *      своей сети или сразу сделать рабочей.
 *   5. Настройки движка (порты, протокол, интерфейс…) — в режиме эксперта.
 *
 * Бэкенд — api/geneva.py; логика — core/geneva_manager.py и
 * core/bypass_engine.py.
 */

const GenevaPage = (() => {
    const POLL_MS = 3000;
    let _pollTimer = null;
    let _inFlight = false;
    let _visibilityHandler = null;
    let _formFilled = false;
    let _settingsFilled = false;
    let _library = [];
    let _last = null;

    const VERDICT = {
        working:    ['status-ok', 'Стратегия срабатывает на трафике'],
        not_firing: ['status-error', 'Пакеты идут через geneva, но ни одно дерево стратегии не сработало — триггер не совпадает с трафиком'],
        no_traffic: ['status-off', 'Пока ни одного пакета: откройте заблокированный сайт или проверьте порты'],
    };

    const STATUS_TEXT = {
        idle: 'Подбор не запускался',
        running: 'Идёт',
        done: 'Закончен',
        stopped: 'Остановлен — можно продолжить',
        interrupted: 'Прерван (перезагрузка или сбой) — можно продолжить',
        not_blocked: 'Сайт открывается без обхода — подбирать нечего',
        error: 'Ошибка',
    };

    function esc(s) {
        return String(s === undefined || s === null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function errText(e) {
        const hint = e && e.data && e.data.hint ? ' — ' + e.data.hint : '';
        return (e && e.message ? e.message : String(e)) + hint;
    }

    function fmtTime(ts) {
        if (!ts) return '';
        const d = new Date(ts > 1e12 ? ts : ts * 1000);
        return d.toLocaleTimeString();
    }

    function fmtDate(ts) {
        if (!ts) return '';
        const d = new Date(ts > 1e12 ? ts : ts * 1000);
        return d.toLocaleString();
    }

    function fmtUptime(ms) {
        const s = Math.floor((ms || 0) / 1000);
        if (s < 60) return s + ' с';
        if (s < 3600) return Math.floor(s / 60) + ' мин';
        return Math.floor(s / 3600) + ' ч ' + Math.floor((s % 3600) / 60) + ' мин';
    }

    function num(n) {
        return (n === undefined || n === null) ? '—' : Number(n).toLocaleString();
    }

    /* ───────── разметка ───────── */

    async function render(container) {
        _formFilled = false;
        _settingsFilled = false;
        container.innerHTML = `
            <div class="page-header">
                <h1>Движок обхода</h1>
                <span class="page-subtitle">Чем обходить блокировки на роутере: nfqws2 или geneva_c</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Чем обходить блокировки</div>
                    <div class="card-body">
                        <div id="gv-engines" class="gv-engines">Загрузка...</div>
                        <div class="form-hint" style="margin-top:8px;">
                            Работает один движок: при переключении второй
                            останавливается (и его автозапуск выключается), а его
                            стратегия и прогресс подбора сохраняются — вернуться
                            можно в любой момент.
                        </div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Движок geneva_c</div>
                    <div class="card-body">
                        <div id="gv-detect"></div>
                        <div id="gv-engine">Загрузка...</div>
                        <div class="gv-actions">
                            <button class="btn btn-primary" id="gv-btn-start">Запустить</button>
                            <button class="btn btn-danger" id="gv-btn-stop">Остановить</button>
                            <button class="btn btn-ghost expert-only" id="gv-btn-pause">Пауза</button>
                            <button class="btn btn-ghost" id="gv-btn-log">Лог</button>
                        </div>
                        <div class="form-group" style="margin-top:12px;">
                            <label class="form-label" for="gv-strategy">Рабочая стратегия</label>
                            <div class="gv-row">
                                <input id="gv-strategy" class="form-control gv-mono gv-grow" placeholder="[TCP:flags:PA]-fragment{tcp:8:True}-| \\/">
                                <button class="btn btn-ghost" id="gv-btn-strategy">Сохранить</button>
                            </div>
                            <div class="form-hint">Стратегия Geneva — свой язык, это не аргументы nfqws2.
                                Работающий движок переключается на неё без перезапуска.</div>
                        </div>
                        <div id="gv-log-box"></div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Подбор стратегии</div>
                    <div class="card-body">
                        <div class="form-hint" style="margin-bottom:10px;">
                            Генетический алгоритм Geneva сам составляет стратегии,
                            проверяет каждую на заблокированном сайте и скрещивает
                            лучшие. Прогресс сохраняется после каждого поколения:
                            остановили, перезагрузили роутер — подбор продолжится
                            с того же места.
                        </div>
                        <div class="gv-form">
                            <div class="form-group">
                                <label class="form-label" for="gv-host">Заблокированный сайт</label>
                                <input id="gv-host" class="form-control" placeholder="rutracker.org">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-probe">Чем проверять</label>
                                <select id="gv-probe" class="form-control">
                                    <option value="tls">TLS (443): ответ сервера на ClientHello</option>
                                    <option value="https">HTTPS (443): полная загрузка страницы (curl)</option>
                                    <option value="http">HTTP (80): полная загрузка страницы</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-size">Глубина поиска</label>
                                <select id="gv-size" class="form-control">
                                    <option value="quick">Быстро: 20 стратегий × 8 поколений</option>
                                    <option value="normal" selected>Обычно: 30 × 15</option>
                                    <option value="deep">Глубоко: 60 × 30 (часы)</option>
                                    <option value="custom">Своя</option>
                                </select>
                            </div>
                            <div class="form-group gv-custom-size hidden">
                                <label class="form-label">Популяция / поколений</label>
                                <div class="gv-row">
                                    <input id="gv-population" type="number" min="4" max="500" class="form-control" value="30">
                                    <input id="gv-generations" type="number" min="1" max="500" class="form-control" value="15">
                                </div>
                            </div>
                            <div class="form-group expert-only">
                                <label class="form-label" for="gv-workers">Проверок одновременно</label>
                                <input id="gv-workers" type="number" min="1" max="8" class="form-control" value="1">
                            </div>
                        </div>
                        <label class="gv-check">
                            <input type="checkbox" id="gv-pause" checked>
                            приостановить работающий обход на время подбора (иначе сайт
                            «откроется» и без стратегии) — он вернётся сам
                        </label>
                        <div class="gv-actions">
                            <button class="btn btn-primary" id="gv-btn-search">Начать подбор</button>
                            <button class="btn btn-primary hidden" id="gv-btn-resume">Продолжить</button>
                            <button class="btn btn-ghost hidden" id="gv-btn-extend" title="Продолжить законченный подбор с того же места">Ещё поколений</button>
                            <button class="btn btn-danger hidden" id="gv-btn-search-stop">Остановить</button>
                            <button class="btn btn-ghost hidden" id="gv-btn-forget">Забыть сохранённый</button>
                        </div>
                        <div id="gv-search"></div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Библиотека Geneva</div>
                    <div class="card-body">
                        <div class="form-hint" style="margin-bottom:8px;">
                            Стратегии из исследований Geneva с долей успеха в той
                            стране, где их нашли. В вашей сети их стоит проверить:
                            выберите несколько и нажмите «Проверить на моей сети»
                            (сайт — из формы подбора).
                        </div>
                        <div class="gv-row" style="margin-bottom:8px;">
                            <select id="gv-lib-country" class="form-control" style="max-width:200px;">
                                <option value="">Все страны</option>
                            </select>
                            <select id="gv-lib-test" class="form-control" style="max-width:160px;">
                                <option value="">Все протоколы</option>
                            </select>
                            <button class="btn btn-ghost" id="gv-btn-eval">Проверить выбранные на моей сети</button>
                        </div>
                        <div id="gv-library">Загрузка...</div>
                    </div>
                </div>
            </div>

            <div class="card-grid expert-only">
                <div class="card">
                    <div class="card-title">Настройки движка geneva</div>
                    <div class="card-body">
                        <div class="gv-form">
                            <div class="form-group">
                                <label class="form-label" for="gv-ports">Порты сервиса</label>
                                <input id="gv-ports" class="form-control" placeholder="80,443">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-proto">Протокол</label>
                                <select id="gv-proto" class="form-control">
                                    <option value="tcp">tcp</option>
                                    <option value="udp">udp</option>
                                    <option value="tcp,udp">tcp,udp</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-iface">WAN-интерфейс</label>
                                <input id="gv-iface" class="form-control" placeholder="пусто — весь трафик">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-firewall">Firewall</label>
                                <select id="gv-firewall" class="form-control">
                                    <option value="auto">auto</option>
                                    <option value="nft">nft</option>
                                    <option value="iptables">iptables</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-first">Только первые N пакетов соединения</label>
                                <input id="gv-first" type="number" min="0" max="1000" class="form-control" placeholder="0 — все">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="gv-loglevel">Уровень лога</label>
                                <select id="gv-loglevel" class="form-control">
                                    <option>error</option><option>warn</option><option>info</option>
                                    <option>debug</option><option>trace</option>
                                </select>
                            </div>
                        </div>
                        <label class="gv-check">
                            <input type="checkbox" id="gv-autostart">
                            поднимать geneva при загрузке роутера (если он выбран движком обхода)
                        </label>
                        <div class="gv-actions">
                            <button class="btn btn-primary" id="gv-btn-settings">Сохранить настройки</button>
                        </div>
                    </div>
                </div>
            </div>
            ${typeof Expert !== 'undefined' ? Expert.noteHtml('Настройки движка geneva (порты, интерфейс, firewall) скрыты') : ''}
        `;

        const on = (id, fn) => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('click', fn);
        };
        on('gv-btn-start', () => _engineAction('start'));
        on('gv-btn-stop', () => _engineAction('stop'));
        on('gv-btn-pause', _togglePause);
        on('gv-btn-log', _loadLog);
        on('gv-btn-strategy', () => _setStrategy(document.getElementById('gv-strategy').value, 'manual'));
        on('gv-btn-search', () => _startSearch(false));
        on('gv-btn-resume', () => _startSearch(true));
        on('gv-btn-extend', () => _extendSearch());
        on('gv-btn-search-stop', _stopSearch);
        on('gv-btn-forget', _forgetSearch);
        on('gv-btn-eval', _evalSelected);
        on('gv-btn-settings', _saveSettings);
        document.getElementById('gv-size').addEventListener('change', _toggleCustomSize);
        document.getElementById('gv-lib-country').addEventListener('change', _renderLibrary);
        document.getElementById('gv-lib-test').addEventListener('change', _renderLibrary);
        container.addEventListener('click', _delegatedClick);

        _visibilityHandler = () => {
            if (document.hidden) _stopPoll();
            else _startPoll();
        };
        document.addEventListener('visibilitychange', _visibilityHandler);

        await Promise.all([_refresh(), _loadConfig(), _loadLibrary()]);
        _startPoll();
    }

    function destroy() {
        _stopPoll();
        if (_visibilityHandler) {
            document.removeEventListener('visibilitychange', _visibilityHandler);
            _visibilityHandler = null;
        }
    }

    function _startPoll() {
        _stopPoll();
        _pollTimer = setInterval(_refresh, POLL_MS);
    }

    function _stopPoll() {
        if (_pollTimer) clearInterval(_pollTimer);
        _pollTimer = null;
    }

    async function _refresh() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            const [st, engines] = await Promise.all([
                API.get('/api/geneva/status'),
                API.get('/api/bypass/engine'),
            ]);
            _last = st;
            _renderEngines(engines);
            _renderDetect(st.detect || {});
            _renderEngine(st.engine || {}, st.active_engine, st.detect || {});
            _renderSearch(st.search || {});
        } catch (e) {
            const el = document.getElementById('gv-engine');
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(errText(e))}</div>`;
        } finally {
            _inFlight = false;
        }
    }

    /* ───────── выбор движка ───────── */

    function _renderEngines(o) {
        const box = document.getElementById('gv-engines');
        if (!box || !o) return;
        const nf = o.nfqws2 || {}, ge = o.geneva || {};
        const tile = (id, title, active, running, lines) => `
            <div class="gv-engine ${active ? 'gv-engine-active' : ''}">
                <div class="gv-engine-head">
                    <span class="status-dot ${running ? 'status-ok' : 'status-off'}"></span>
                    <strong>${esc(title)}</strong>
                    ${active ? '<span class="badge badge-success">выбран</span>' : ''}
                </div>
                <div class="gv-engine-body">${lines.join('')}</div>
                ${active ? '' : `<button class="btn btn-primary btn-sm" data-switch="${id}">Обходить через ${esc(title)}</button>`}
            </div>`;
        const nfLines = [
            `<div>${nf.running ? 'Работает' : 'Остановлен'}</div>`,
            `<div class="text-muted">Стратегия: ${esc(nf.strategy_name || nf.strategy_id || 'не выбрана')}</div>`,
            `<div class="text-muted">Автозапуск: ${nf.autostart ? 'да' : 'нет'}</div>`,
        ];
        if (nf.scan_resume && nf.scan_resume.next_index) {
            const r = nf.scan_resume;
            nfLines.push(`<div class="text-muted">Прерванный подбор: ${esc(r.target)}, с ${r.next_index + 1}-й,
                найдено ${r.working_count} — <a href="#scan">продолжить</a></div>`);
        }
        const s = ge.search || {};
        const geLines = [
            `<div>${!ge.installed ? 'Не установлен' : (ge.running ? 'Работает' : 'Остановлен')}</div>`,
            `<div class="text-muted gv-ellipsis" title="${esc(ge.strategy)}">Стратегия: ${ge.strategy ? `<span class="gv-mono">${esc(ge.strategy)}</span>` : 'не выбрана'}</div>`,
            `<div class="text-muted">Автозапуск: ${ge.autostart ? 'да' : 'нет'}</div>`,
        ];
        if (s.running) {
            geLines.push(`<div class="text-muted">Идёт подбор: ${s.kind === 'evolve' ? `поколение ${s.generation} из ${s.generations}` : 'проверка стратегий'}</div>`);
        } else if (s.can_resume) {
            geLines.push(`<div class="text-muted">Подбор для ${esc(s.target)} прерван — можно продолжить ниже</div>`);
        }
        box.innerHTML = tile('nfqws2', 'nfqws2', o.active === 'nfqws2', nf.running, nfLines)
                      + tile('geneva', 'geneva_c', o.active === 'geneva', ge.running, geLines);
    }

    async function _switchEngine(target) {
        const name = target === 'geneva' ? 'geneva_c' : 'nfqws2';
        const other = target === 'geneva' ? 'nfqws2' : 'geneva_c';
        const ok = await Confirm.show('Переключить движок обхода',
            `Обход пойдёт через <strong>${name}</strong>. ${other} будет остановлен,
             его автозапуск выключен; стратегия и прогресс подбора ${other}
             сохранятся. На пару секунд обход пропадёт.`,
            { confirmLabel: 'Переключить' });
        if (!ok) return;
        try {
            let res;
            try {
                res = await API.post('/api/bypass/engine', { engine: target, start: true }, { timeout: 60000 });
            } catch (e) {
                if (e.data && e.data.error_code === 'no_strategy') {
                    const again = await Confirm.show('У geneva нет рабочей стратегии',
                        `${esc(e.data.error)}. Выбрать geneva движком без запуска? nfqws2
                         остановится, и обхода не будет, пока вы не выберете стратегию
                         в библиотеке или не найдёте её подбором.`,
                        { confirmLabel: 'Выбрать без запуска', danger: true });
                    if (!again) return;
                    res = await API.post('/api/bypass/engine', { engine: target, start: false }, { timeout: 60000 });
                } else {
                    throw e;
                }
            }
            if (res.warning) Toast.warning ? Toast.warning(res.warning) : Toast.error(res.warning);
            else Toast.success(`Обход идёт через ${name}`);
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    /* ───────── движок geneva ───────── */

    function _renderDetect(d) {
        const el = document.getElementById('gv-detect');
        if (!el) return;
        if (!d.installed) {
            el.innerHTML = `
                <div class="gv-note">
                    geneva_c не установлен. Сборка ставится из официального релиза
                    <a href="https://github.com/avatarDD/geneva_c/releases" target="_blank" rel="noopener">avatarDD/geneva_c</a>
                    с проверкой sha256.
                    <button class="btn btn-primary btn-sm" data-action="install">Установить</button>
                </div>`;
            return;
        }
        el.innerHTML = `<div class="text-muted" style="font-size:12px;margin-bottom:6px;">
            geneva ${esc(d.version)} · ${esc(d.arch)} · ${esc(d.binary)}
            ${d.hint ? `<div class="text-error">${esc(d.hint)}</div>` : ''}</div>`;
    }

    function _renderEngine(e, active, d) {
        const el = document.getElementById('gv-engine');
        if (!el) return;
        let cls = 'status-off', text = 'Остановлен';
        if (e.running) {
            cls = e.state === 'paused' ? 'status-error' : 'status-ok';
            text = e.state === 'paused' ? 'На паузе — пакеты идут без изменений' : 'Работает';
        }
        const st = e.stats || {};
        const verdict = e.running && st.verdict ? VERDICT[st.verdict] : null;
        const trees = (st.trees || []).map(t => `
            <tr><td>${t.dir === 'out' ? 'исходящие' : 'входящие'}</td>
                <td class="gv-mono">${esc(t.tree)}</td><td>${num(t.fired)}</td></tr>`).join('');
        const feed = (e.events || []).slice().reverse().map(ev => `
            <div class="gv-feed-${esc(ev.level)}"><span class="text-muted">${fmtTime(ev.ts)}</span> ${esc(ev.text)}</div>`).join('');
        el.innerHTML = `
            <div class="gv-row">
                <span class="status-dot ${cls}"></span><span>${text}</span>
                ${e.pid ? `<span class="text-muted">PID ${e.pid}</span>` : ''}
                ${e.uptime_ms ? `<span class="text-muted">${fmtUptime(e.uptime_ms)}</span>` : ''}
                ${e.firewall ? `<span class="text-muted">правила: ${esc(e.firewall)}</span>` : ''}
                <span class="text-muted">порты ${esc(e.ports)} / ${esc(e.proto)}</span>
            </div>
            ${active !== 'geneva' ? `<div class="form-hint">Сейчас обход идёт через nfqws2. Чтобы запустить geneva,
                выберите его в плитке выше — nfqws2 остановится.</div>` : ''}
            ${verdict ? `<div class="gv-verdict"><span class="status-dot ${verdict[0]}"></span>${esc(verdict[1])}</div>` : ''}
            ${e.running && st.pkts_out !== undefined ? `
            <div class="gv-stats">
                <div><span>${num(st.pkts_out)}</span>исходящих пакетов</div>
                <div><span>${num(st.pkts_in)}</span>входящих</div>
                <div><span>${num(st.triggered)}</span>сработала стратегия</div>
                <div><span>${num(st.modified)}</span>изменено</div>
                <div><span>${num(st.injected)}</span>отправлено доп. пакетов</div>
                <div><span>${num(st.dropped)}</span>отброшено</div>
                <div class="${st.errors ? 'gv-bad' : ''}"><span>${num(st.errors)}</span>ошибок</div>
            </div>` : ''}
            ${trees ? `<details class="expert-only" style="margin-top:8px;"><summary>Срабатывания деревьев</summary>
                <table class="table"><tr><th>Направление</th><th>Дерево</th><th>Сработало</th></tr>${trees}</table></details>` : ''}
            ${e.control_error ? `<div class="text-error" style="font-size:12px;">Управляющий сокет: ${esc(e.control_error)}</div>` : ''}
            ${feed ? `<div class="gv-feed">${feed}</div>` : ''}
        `;
        const input = document.getElementById('gv-strategy');
        if (input && document.activeElement !== input && !input.dataset.dirty) {
            input.value = e.strategy || '';
        }
        if (input && !input.dataset.bound) {
            input.dataset.bound = '1';
            input.addEventListener('input', () => { input.dataset.dirty = '1'; });
        }
        const startBtn = document.getElementById('gv-btn-start');
        const stopBtn = document.getElementById('gv-btn-stop');
        const pauseBtn = document.getElementById('gv-btn-pause');
        if (startBtn) {
            startBtn.disabled = !!e.running || !d.installed || active !== 'geneva';
            startBtn.title = active !== 'geneva' ? 'Сначала выберите geneva_c движком обхода (плитка выше)' : '';
        }
        if (stopBtn) stopBtn.disabled = !e.running;
        if (pauseBtn) {
            pauseBtn.disabled = !e.running;
            pauseBtn.textContent = e.state === 'paused' ? 'Снять с паузы' : 'Пауза';
        }
    }

    async function _engineAction(action) {
        try {
            const res = await API.post('/api/geneva/' + action, {}, { timeout: 30000 });
            Toast.success(action === 'start' ? (res.ready ? 'geneva запущен' : 'geneva запущен, правила ставятся')
                                             : 'geneva остановлен');
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _togglePause() {
        const paused = _last && _last.engine && _last.engine.state === 'paused';
        try {
            await API.post(paused ? '/api/geneva/resume' : '/api/geneva/pause', {});
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _setStrategy(strategy, source) {
        strategy = (strategy || '').trim();
        if (!strategy) {
            Toast.error('Стратегия пустая');
            return;
        }
        try {
            const res = await API.post('/api/geneva/strategy', { strategy, source });
            const input = document.getElementById('gv-strategy');
            if (input) { input.value = res.strategy; delete input.dataset.dirty; }
            Toast.success(res.applied_live ? 'Стратегия сохранена и уже работает' : 'Стратегия сохранена');
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _loadLog() {
        const box = document.getElementById('gv-log-box');
        if (!box) return;
        const which = _last && _last.search && _last.search.running ? 'job' : 'run';
        try {
            const r = await API.get('/api/geneva/log?lines=200&which=' + which);
            const text = (r.lines || []).join('\n').trim();
            box.innerHTML = text ? `<pre class="usque-diagnostic">${esc(text)}</pre>`
                                 : '<div class="form-hint">Лог пуст.</div>';
        } catch (e) {
            box.innerHTML = `<div class="text-error">${esc(errText(e))}</div>`;
        }
    }

    async function _install() {
        Toast.success('Скачиваю geneva из релиза…');
        try {
            const res = await API.post('/api/geneva/install', {}, { timeout: 180000 });
            Toast.success('geneva установлен: ' + (res.version || res.tag || ''));
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
        _loadLibrary();
    }

    /* ───────── подбор ───────── */

    const SIZES = { quick: [20, 8], normal: [30, 15], deep: [60, 30] };

    function _toggleCustomSize() {
        const v = document.getElementById('gv-size').value;
        document.querySelectorAll('.gv-custom-size').forEach(el => el.classList.toggle('hidden', v !== 'custom'));
    }

    function _searchParams() {
        const size = document.getElementById('gv-size').value;
        let [population, generations] = SIZES[size] || [
            parseInt(document.getElementById('gv-population').value, 10) || 30,
            parseInt(document.getElementById('gv-generations').value, 10) || 15];
        return {
            host: (document.getElementById('gv-host').value || '').trim(),
            probe: document.getElementById('gv-probe').value,
            population, generations,
            workers: parseInt(document.getElementById('gv-workers').value, 10) || 1,
            pause_bypass: !!document.getElementById('gv-pause').checked,
        };
    }

    async function _startSearch(resume) {
        let body;
        if (resume) {
            body = { resume: true };
        } else {
            body = _searchParams();
            if (!body.host) {
                Toast.error('Укажите заблокированный сайт');
                return;
            }
            const st = _last && _last.search;
            if (st && st.can_resume) {
                const ok = await Confirm.show('Начать новый подбор?',
                    `Сохранённый подбор для ${esc(st.target)} будет заменён новым
                     (найденные стратегии останутся в базе оценок).`,
                    { confirmLabel: 'Начать заново', danger: true });
                if (!ok) return;
            }
        }
        try {
            const res = await API.post('/api/geneva/search/start', body, { timeout: 60000 });
            Toast.success(resume ? 'Подбор продолжен' : 'Подбор запущен');
            if (res.paused_engine) {
                Toast.success(`Обход через ${res.paused_engine} приостановлен на время подбора`);
            }
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _extendSearch() {
        // Законченный поиск продлевается на столько же поколений, сколько
        // в пресете «быстро», — без новых вопросов к пользователю.
        try {
            await API.post('/api/geneva/search/start', { resume: true, more_generations: SIZES.quick[1] }, { timeout: 60000 });
            Toast.success(`Подбор продлён на ${SIZES.quick[1]} поколений`);
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _stopSearch() {
        try {
            const res = await API.post('/api/geneva/search/stop', {}, { timeout: 60000 });
            Toast.success(res.can_resume ? 'Подбор остановлен — продолжить можно позже' : 'Остановлено');
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    async function _forgetSearch() {
        const ok = await Confirm.show('Забыть сохранённый подбор?',
            'Продолжить его будет нельзя. База оценок (найденные стратегии) останется.',
            { confirmLabel: 'Забыть', danger: true });
        if (!ok) return;
        try {
            await API.post('/api/geneva/search/forget', {});
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    function _fitnessBadge(f) {
        if (f === undefined || f === null) return '<span class="badge badge-muted">—</span>';
        return Number(f) > 0 ? `<span class="badge badge-success">${esc(f)} · работает</span>`
                             : `<span class="badge badge-danger">${esc(f)}</span>`;
    }

    function _renderSearch(s) {
        const box = document.getElementById('gv-search');
        if (!box) return;
        const p = s.params || {};
        if (!_formFilled && p.host) {
            _formFilled = true;
            document.getElementById('gv-host').value = p.host;
            document.getElementById('gv-probe').value = p.probe || 'tls';
            const size = Object.keys(SIZES).find(k => SIZES[k][0] === p.population && SIZES[k][1] === p.generations);
            document.getElementById('gv-size').value = size || 'custom';
            document.getElementById('gv-population').value = p.population || 30;
            document.getElementById('gv-generations').value = p.generations || 15;
            document.getElementById('gv-workers').value = p.workers || 1;
            _toggleCustomSize();
        }
        const running = !!s.running;
        const show = (id, on) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !on); };
        show('gv-btn-search-stop', running);
        show('gv-btn-resume', !running && s.can_resume);
        show('gv-btn-extend', !running && s.can_extend);
        show('gv-btn-forget', !running && (s.can_resume || ['done', 'stopped', 'interrupted', 'not_blocked', 'error'].includes(s.status)));
        const startBtn = document.getElementById('gv-btn-search');
        if (startBtn) startBtn.disabled = running;
        if (!s.status || s.status === 'idle') {
            box.innerHTML = '';
            return;
        }
        const kind = s.kind === 'eval' ? 'Проверка стратегий' : 'Подбор';
        const pct = Math.max(0, Math.min(100, s.percent || 0));
        const progress = s.kind === 'eval'
            ? `проверено ${s.done || 0} из ${s.total || 0}`
            : `поколение ${Math.max(0, s.generation)} из ${s.generations}`;
        const baseline = s.baseline ? (s.baseline.blocked
            ? `<div class="text-muted">Без обхода сайт заблокирован: ${esc(s.baseline.outcome)} — ищем стратегию.</div>`
            : '<div class="text-error">Без обхода сайт открывается — подбирать нечего.</div>') : '';
        const best = s.best ? `<div style="margin-top:6px;">Лучшая пока: ${_fitnessBadge(s.best_fitness)}
                <code class="gv-mono">${esc(s.best)}</code></div>` : '';
        const feed = (s.events || []).slice().reverse().map(ev => `
            <div class="gv-feed-${esc(ev.level)}"><span class="text-muted">${fmtTime(ev.ts)}</span> ${esc(ev.text)}</div>`).join('');
        const evals = (s.evals || []).slice().reverse().slice(0, 10).map(ev => `
            <tr><td>${_fitnessBadge(ev.fitness)}</td><td>${esc(ev.outcome_text)}</td>
                <td class="gv-mono gv-ellipsis" title="${esc(ev.strategy)}">${esc(ev.strategy)}</td></tr>`).join('');
        const results = (s.results || []).filter(r => r.strategy).map(r => `
            <tr><td>${_fitnessBadge(r.avg_fitness)}</td><td>${num(r.runs)}</td>
                <td class="gv-mono gv-ellipsis" title="${esc(r.strategy)}">${esc(r.strategy)}</td>
                <td>${Number(r.avg_fitness) > 0 ? `<button class="btn btn-ghost btn-sm" data-use="${esc(r.strategy)}">Сделать рабочей</button>` : ''}</td></tr>`).join('');
        box.innerHTML = `
            <div class="gv-search-head">
                <strong>${kind}: ${esc(STATUS_TEXT[s.status] || s.status)}</strong>
                <span class="text-muted">${esc(s.target)} · начат ${fmtDate(s.started_at)}</span>
            </div>
            <div class="diag-progress" style="margin:8px 0;">
                <div class="diag-progress-track"><div class="diag-progress-bar" style="width:${pct}%"></div></div>
                <div class="diag-progress-text">${progress} (${pct}%)</div>
            </div>
            ${baseline}
            ${s.paused_engine && running ? `<div class="text-muted">Обход через ${esc(s.paused_engine)} приостановлен и вернётся после подбора.</div>` : ''}
            ${s.status === 'error' ? `<div class="text-error">${esc(s.error || s.exit_text)}</div>` : ''}
            ${best}
            ${results ? `<h4 style="margin:12px 0 4px;">Найдено</h4>
                <table class="table"><tr><th>Фитнес</th><th>Оценок</th><th>Стратегия</th><th></th></tr>${results}</table>
                <div class="form-hint">Фитнес больше нуля — сайт открылся; чем выше, тем короче и надёжнее стратегия.</div>` : ''}
            ${evals ? `<details ${running ? 'open' : ''} style="margin-top:8px;"><summary>Последние проверки</summary>
                <table class="table"><tr><th>Фитнес</th><th>Исход</th><th>Стратегия</th></tr>${evals}</table></details>` : ''}
            ${feed ? `<div class="gv-feed">${feed}</div>` : ''}
        `;
    }

    /* ───────── библиотека ───────── */

    async function _loadLibrary() {
        const box = document.getElementById('gv-library');
        try {
            const res = await API.get('/api/geneva/library');
            _library = res.items || [];
        } catch (e) {
            _library = [];
            if (box) box.innerHTML = `<div class="text-muted">${esc(errText(e))}</div>`;
            return;
        }
        const fill = (id, key) => {
            const sel = document.getElementById(id);
            if (!sel) return;
            const values = [...new Set(_library.map(i => i[key]).filter(Boolean))].sort();
            sel.innerHTML = sel.options[0].outerHTML + values.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
        };
        fill('gv-lib-country', 'country');
        fill('gv-lib-test', 'test');
        _renderLibrary();
    }

    function _renderLibrary() {
        const box = document.getElementById('gv-library');
        if (!box) return;
        const country = document.getElementById('gv-lib-country').value;
        const test = document.getElementById('gv-lib-test').value;
        const items = _library.filter(i => (!country || i.country === country) && (!test || i.test === test))
                              .sort((a, b) => (b.rate || 0) - (a.rate || 0));
        if (!items.length) {
            box.innerHTML = '<div class="text-muted">Нет стратегий (geneva не установлен или фильтр пуст).</div>';
            return;
        }
        box.innerHTML = `<div class="gv-scroll"><table class="table">
            <tr><th class="gv-col-pick"></th><th>Успех</th><th>Где</th><th>Описание</th><th>Стратегия</th><th></th></tr>
            ${items.map(i => `
                <tr><td class="gv-col-pick">${i.server_side ? '' : `<input type="checkbox" class="gv-lib-pick" value="${esc(i.strategy)}">`}</td>
                    <td>${esc(i.rate)}%</td>
                    <td>${esc(i.country)} / ${esc(i.test)}${i.server_side ? ' <span class="badge badge-muted">server-side</span>' : ''}</td>
                    <td>${esc(i.description)}</td>
                    <td class="gv-mono gv-ellipsis" title="${esc(i.strategy)}">${esc(i.strategy)}</td>
                    <td>${i.server_side ? '' : `<button class="btn btn-ghost btn-sm" data-use-lib="${esc(i.strategy)}">Сделать рабочей</button>`}</td></tr>`).join('')}
        </table></div>
        <div class="form-hint">server-side — стратегии для сервера, на роутере клиента они не помогают.</div>`;
    }

    async function _evalSelected() {
        const picked = [...document.querySelectorAll('.gv-lib-pick:checked')].map(el => el.value);
        if (!picked.length) {
            Toast.error('Отметьте стратегии в таблице');
            return;
        }
        const params = _searchParams();
        if (!params.host) {
            Toast.error('Укажите заблокированный сайт в форме подбора');
            return;
        }
        try {
            const res = await API.post('/api/geneva/eval', Object.assign({ strategies: picked }, params), { timeout: 60000 });
            Toast.success('Проверяю ' + picked.length + ' стратегий' +
                          (res.paused_engine ? '; обход приостановлен на время проверки' : ''));
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    /* ───────── настройки ───────── */

    async function _loadConfig() {
        try {
            const c = await API.get('/api/geneva/config');
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
            set('gv-ports', c.ports || '80,443');
            set('gv-proto', c.proto || 'tcp');
            set('gv-iface', c.iface || '');
            set('gv-firewall', c.firewall || 'auto');
            set('gv-first', c.first || 0);
            set('gv-loglevel', c.log_level || 'info');
            const auto = document.getElementById('gv-autostart');
            if (auto) auto.checked = !!c.autostart;
            const s = c.search || {};
            if (!_formFilled && s.host) {
                set('gv-host', s.host);
                set('gv-probe', s.probe || 'tls');
            }
            const pause = document.getElementById('gv-pause');
            if (pause && s.pause_bypass === false) pause.checked = false;
            _settingsFilled = true;
        } catch (_) { /* форма останется с умолчаниями */ }
    }

    async function _saveSettings() {
        const val = id => document.getElementById(id).value;
        const body = {
            ports: val('gv-ports'), proto: val('gv-proto'), iface: val('gv-iface'),
            firewall: val('gv-firewall'), first: parseInt(val('gv-first'), 10) || 0,
            log_level: val('gv-loglevel'),
            autostart: !!document.getElementById('gv-autostart').checked,
        };
        try {
            const res = await API.put('/api/geneva/config', body);
            if (res.restart_needed) {
                const ok = await Confirm.show('Перезапустить geneva?',
                    'Порты и прочие параметры движок подхватит только после перезапуска.',
                    { confirmLabel: 'Перезапустить' });
                if (ok) await _engineAction('restart');
            } else {
                Toast.success('Настройки сохранены');
            }
        } catch (e) {
            Toast.error(errText(e));
        }
    }

    /* ───────── кнопки в таблицах ───────── */

    async function _delegatedClick(ev) {
        const t = ev.target.closest('button');
        if (!t) return;
        if (t.dataset.switch) return _switchEngine(t.dataset.switch);
        if (t.dataset.action === 'install') return _install();
        if (t.dataset.use) return _setStrategy(t.dataset.use, 'search');
        if (t.dataset.useLib) return _setStrategy(t.dataset.useLib, 'library');
    }

    return { render, destroy };
})();
