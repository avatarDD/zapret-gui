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

    // Части страницы. Раздел «Обход DPI» собирает их по задачам:
    // «Движок обхода» — engines, «Управление» → geneva_c — engine и
    // settings, «Стратегии» → geneva_c — library, «Подбор стратегий» →
    // geneva_c — search (web/js/components/engine_tabs.js).
    const ALL_SECTIONS = ['auto', 'engines', 'engine', 'search', 'found', 'library', 'settings'];
    // Режим «Авто»: показывать и сервисы без проблем (галочка).
    let _autoAll = false;
    let _autoBusy = false;
    let _sections = new Set(ALL_SECTIONS);
    let _renderToken = 0;

    async function render(container, opts) {
        opts = opts || {};
        const token = ++_renderToken;
        _stopPoll();
        if (_visibilityHandler) {
            document.removeEventListener('visibilitychange', _visibilityHandler);
            _visibilityHandler = null;
        }
        _formFilled = false;
        _settingsFilled = false;
        _sections = new Set(opts.sections || ALL_SECTIONS);
        const S = id => _sections.has(id);
        const header = opts.header === false ? '' : `
            <div class="page-header">
                <h1>${esc(opts.title || 'Движок обхода')}</h1>
                <span class="page-subtitle">${esc(opts.subtitle || 'Чем обходить блокировки на роутере: nfqws2 или geneva_c')}</span>
            </div>`;
        container.innerHTML = `
            ${header}
            ${S('auto') ? `
            <div class="card-grid">
                <div class="card">
                    <div class="card-title gv-auto-head">
                        <span>${esc(_tr('geneva.auto.title'))}</span>
                        <label class="gv-auto-switch">
                            <input type="checkbox" id="gv-auto-toggle">
                            <span id="gv-auto-toggle-label">${esc(_tr('geneva.auto.off_short'))}</span>
                        </label>
                    </div>
                    <div class="card-body">
                        <div class="form-hint" style="margin-bottom:8px;">${esc(_tr('geneva.auto.about'))}</div>
                        <div id="gv-auto">${esc(_tr('common.loading'))}</div>
                        <div id="gv-nat" class="gv-nat" hidden>
                            <label class="gv-check">
                                <input type="checkbox" id="gv-nat-toggle">
                                <span>${esc(_tr('geneva.nat.label'))}</span>
                                <span id="gv-nat-state" class="text-muted"></span>
                            </label>
                            <div class="form-hint">${esc(_tr('geneva.nat.hint'))}</div>
                        </div>
                    </div>
                </div>
            </div>` : ''}
            ${S('engines') ? `
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
                        <div class="gv-next">
                            Дальше — по задаче, у каждой вкладки nfqws2 и geneva_c:
                            <a href="#control">Управление</a> ·
                            <a href="#strategies">Стратегии</a> ·
                            <a href="#scan">Подбор стратегий</a>
                        </div>
                    </div>
                </div>
            </div>` : ''}
            ${S('engine') ? `
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
            </div>` : ''}
            ${S('search') ? `
            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Подбор стратегии geneva_c</div>
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
            </div>` : ''}
            ${S('found') ? `
            <div class="card-grid">
                <div class="card">
                    <div class="card-title">${esc(_tr('geneva.found.title'))}</div>
                    <div class="card-body">
                        <div class="form-hint" style="margin-bottom:8px;">${esc(_tr('geneva.found.about'))}</div>
                        <div class="gv-actions" style="margin-bottom:8px;">
                            <button class="btn btn-ghost btn-sm" data-action="found-export">${esc(_tr('geneva.found.export'))}</button>
                            <button class="btn btn-ghost btn-sm" data-action="found-import">${esc(_tr('geneva.found.import'))}</button>
                            <input type="file" id="gv-found-file" accept=".json,.txt,application/json,text/plain" hidden>
                        </div>
                        <div id="gv-found">${esc(_tr('common.loading'))}</div>
                    </div>
                </div>
            </div>` : ''}
            ${S('library') ? `
            <div class="card-grid">
                <details class="card gv-lib-details" id="gv-lib-details" ${S('found') ? '' : 'open'}>
                    <summary class="card-title">${esc(_tr(S('found') ? 'geneva.found.library' : 'geneva.found.library_title'))}</summary>
                    <div class="card-body">
                        <div class="form-hint" style="margin-bottom:8px;">
                            Стратегии из исследований Geneva с долей успеха в той
                            стране, где их нашли. В вашей сети их стоит проверить:
                            укажите заблокированный сайт, отметьте несколько и
                            нажмите «Проверить на моей сети».
                        </div>
                        <div class="gv-row" style="margin-bottom:8px;">
                            <input id="gv-lib-host" class="form-control" style="max-width:220px;" placeholder="заблокированный сайт">
                            <select id="gv-lib-country" class="form-control" style="max-width:200px;">
                                <option value="">Все страны</option>
                            </select>
                            <select id="gv-lib-test" class="form-control" style="max-width:160px;">
                                <option value="">Все протоколы</option>
                            </select>
                            <button class="btn btn-ghost" id="gv-btn-eval">Проверить выбранные на моей сети</button>
                        </div>
                        <div id="gv-library">Загрузка...</div>
                        ${S('search') ? '' : '<div id="gv-search"></div>'}
                    </div>
                </details>
            </div>` : ''}
            ${S('settings') ? `
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
            ${typeof Expert !== 'undefined' ? Expert.noteHtml('Настройки движка geneva (порты, интерфейс, firewall) скрыты') : ''}` : ''}
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
        const toggle = document.getElementById('gv-auto-toggle');
        if (toggle) toggle.addEventListener('change', () => _autoToggle(toggle.checked));
        const ffile = document.getElementById('gv-found-file');
        if (ffile) ffile.addEventListener('change', () => {
            _importFound(ffile.files && ffile.files[0]);
            ffile.value = '';
        });
        const nat = document.getElementById('gv-nat-toggle');
        if (nat) nat.addEventListener('change', () => _natToggle(nat.checked));
        const onChange = (id, fn) => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('change', fn);
        };
        onChange('gv-size', _toggleCustomSize);
        onChange('gv-lib-country', _renderLibrary);
        onChange('gv-lib-test', _renderLibrary);
        container.addEventListener('click', _delegatedClick);

        _visibilityHandler = () => {
            if (document.hidden) _stopPoll();
            else _startPoll();
        };
        document.addEventListener('visibilitychange', _visibilityHandler);

        // Библиотека исследований под «Стратегиями» свёрнута: geneva
        // library зовём, только когда её раскрыли.
        const libDetails = document.getElementById('gv-lib-details');
        let libLoaded = false;
        const loadLib = () => {
            if (libLoaded || !libDetails || !libDetails.open) return null;
            libLoaded = true;
            return _loadLibrary();
        };
        if (libDetails) libDetails.addEventListener('toggle', loadLib);
        await Promise.all([_refresh(), _loadConfig(),
                           S('auto') ? _loadNat() : null,
                           S('library') ? loadLib() : null,
                           S('found') ? _loadFound() : null]);
        // Пока ждали ответы, со страницы ушли (destroy) или её
        // перерисовали: опрос от старого рендера тёк бы вечно.
        if (token !== _renderToken) return;
        _startPoll();
    }

    function destroy() {
        _renderToken++;
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
            const [st, engines, auto] = await Promise.all([
                API.get('/api/geneva/status'),
                _sections.has('engines') ? API.get('/api/bypass/engine') : null,
                _sections.has('auto') ? API.get('/api/geneva/auto' + (_autoAll ? '?all=1' : '')) : null,
            ]);
            _last = st;
            _renderAuto(auto);
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

    /* ───────── режим «Авто» ───────── */

    /** Перевод с подстановкой; ключа нет в словаре — сам ключ. */
    function _tr(key, vars) {
        return (typeof i18n !== 'undefined') ? i18n.t(key, vars || {}) : key;
    }

    const AUTO_BADGE = {
        applied: 'badge-success', degraded: 'badge-warning',
        searching: 'badge-info', blocked: 'badge-danger',
        suspected: 'badge-warning', not_found: 'badge-danger',
        ip_blocked: 'badge-danger', fallback: 'badge-muted',
        not_blocked: 'badge-muted', watching: 'badge-muted',
    };

    function _renderAuto(a) {
        const box = document.getElementById('gv-auto');
        if (!box || !a) return;
        const toggle = document.getElementById('gv-auto-toggle');
        const label = document.getElementById('gv-auto-toggle-label');
        if (toggle && !_autoBusy) toggle.checked = !!a.enabled;
        if (label) label.textContent = _tr(a.enabled ? 'geneva.auto.on' : 'geneva.auto.off_short');
        if (!a.enabled) {
            box.innerHTML = `<div class="text-muted">${esc(_tr('geneva.auto.off'))}</div>`
                + _autoProblems(a);
            return;
        }
        const c = a.counts || {};
        const applied = (c.applied || 0) + (c.degraded || 0);
        const busy = (c.suspected || 0) + (c.blocked || 0) + (c.searching || 0);
        const nobypass = (c.not_found || 0) + (c.ip_blocked || 0);
        const phase = a.running ? _tr('geneva.auto.phase.' + (a.phase || 'watching'))
                                : _tr('geneva.auto.waiting');
        const sr = a.search || {};
        const par = sr.running && sr.workers
            ? ` (${esc(_tr('geneva.auto.parallel', { done: sr.done || 0, total: sr.total || '?', workers: sr.workers }))})` : '';
        const searchLine = sr.running && sr.name
            ? ` · ${esc(sr.name)}: ${esc(_tr('geneva.auto.phase.searching'))}${par}` : '';
        const rows = (a.services || []).map(s => {
            const trying = s.status === 'searching' && a.search && a.search.key === s.key
                && a.search.strategy ? _tr('geneva.auto.trying', { strategy: a.search.strategy }) : '';
            const status = _tr('geneva.auto.as.' + s.status);
            return `<tr>
                <td title="${esc(s.key)}">${esc(s.name || s.key)}</td>
                <td><span class="badge ${AUTO_BADGE[s.status] || 'badge-muted'}">${esc(status === 'geneva.auto.as.' + s.status ? s.status_text : status)}</span></td>
                <td class="text-muted">${esc(trying || s.why || '')}</td>
                <td class="gv-mono gv-ellipsis" title="${esc(s.strategy || '')}">${esc(s.strategy || '—')}</td>
                <td><button class="btn btn-ghost btn-sm" data-auto-reset="${esc(s.key)}" title="${esc(_tr('geneva.auto.reset_tip'))}">${esc(_tr('geneva.auto.reset'))}</button></td>
            </tr>`;
        }).join('');
        const table = rows ? `
            <div class="table-wrap"><table class="table gv-auto-table">
                <thead><tr>
                    <th>${esc(_tr('geneva.auto.col_service'))}</th>
                    <th>${esc(_tr('geneva.auto.col_status'))}</th>
                    <th>${esc(_tr('geneva.auto.col_why'))}</th>
                    <th>${esc(_tr('geneva.auto.col_strategy'))}</th>
                    <th></th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table></div>` : `<div class="text-muted">${esc(_tr('geneva.auto.empty'))}</div>`;
        const groups = (a.groups || []).map(g => {
            const st = g.stats || {}, rate = g.rate || {};
            return `<li><span class="badge badge-ghost">${esc(_tr('geneva.auto.queue', { queue: g.queue }))}</span>
                <span class="gv-mono">${esc(g.strategy)}</span>
                <div class="text-muted">${esc((g.services || []).length)} · ${esc((g.targets || []).join('; '))}</div>
                <div class="text-muted">${esc(_tr('geneva.auto.counters', {
                    pkts: num((st.pkts_out || 0) + (st.pkts_in || 0)),
                    rate: (rate.pkts_out || 0) + (rate.pkts_in || 0),
                    triggered: num(st.triggered || 0) }))}${g.error ? ' · <span class="text-error">' + esc(g.error) + '</span>' : ''}</div>
            </li>`;
        }).join('');
        // Опрос перерисовывает карточку: раскрытые блоки не должны
        // захлопываться сами.
        const opened = new Set(Array.from(box.querySelectorAll
            ? box.querySelectorAll('details[open]') : []).map(d => d.dataset.k));
        const journal = (a.journal || []).slice(-60).reverse().map(j =>
            `<div class="gv-auto-log-${esc(j.level)}"><span class="text-muted">${esc(fmtTime(j.ts))}</span> ${esc(j.text)}</div>`).join('');
        box.innerHTML = `
            <div class="gv-auto-status"><strong>${esc(phase)}</strong>${searchLine}</div>
            <div class="text-muted">${esc(_tr('geneva.auto.summary', {
                total: a.total || 0, applied, busy, nobypass, flows: a.connections || 0 }))}</div>
            ${_autoProblems(a)}
            <label class="gv-check"><input type="checkbox" id="gv-auto-all" ${_autoAll ? 'checked' : ''}>
                ${esc(_tr('geneva.auto.show_all'))}</label>
            ${table}
            <details class="gv-auto-details" data-k="groups" ${opened.has('groups') ? 'open' : ''}><summary>${esc(_tr('geneva.auto.groups'))} (${(a.groups || []).length})</summary>
                ${groups ? `<ul class="gv-auto-groups">${groups}</ul>` : `<div class="text-muted">${esc(_tr('geneva.auto.no_groups'))}</div>`}
            </details>
            <details class="gv-auto-details" data-k="log" ${opened.has('log') ? 'open' : ''}><summary>${esc(_tr('geneva.auto.log'))}</summary>
                <div class="gv-auto-log">${journal}</div>
            </details>`;
        const all = document.getElementById('gv-auto-all');
        if (all) all.addEventListener('change', () => { _autoAll = all.checked; _refresh(); });
    }

    function _autoProblems(a) {
        const list = (a.problems || []).slice();
        if (a.offload) list.unshift(_tr('geneva.auto.offload'));
        return list.length ? `<div class="text-error">${list.map(esc).join('<br>')}</div>` : '';
    }

    async function _autoToggle(on) {
        _autoBusy = true;
        try {
            if (!on) {
                await API.post('/api/geneva/auto/disable', {}, { timeout: 60000 });
                Toast.info(_tr('geneva.auto.disabled'));
                return;
            }
            try {
                await API.post('/api/geneva/auto/enable', {}, { timeout: 60000 });
            } catch (e) {
                if (!(e.data && e.data.error_code === 'need_confirm')) throw e;
                const ok = await Confirm.show(_tr('geneva.auto.confirm_title'),
                    esc(_tr('geneva.auto.confirm_text')),
                    { confirmLabel: _tr('geneva.auto.confirm_ok') });
                if (!ok) return;
                await API.post('/api/geneva/auto/enable', { confirm: true }, { timeout: 90000 });
            }
            Toast.success(_tr('geneva.auto.enabled'));
        } catch (e) {
            Toast.error(errText(e) + (e.data && e.data.hint ? ' — ' + e.data.hint : ''));
        } finally {
            _autoBusy = false;
            _refresh();
        }
    }

    /* ───────── ускорение NAT роутера ───────── */
    // Опросом не читается: на Keenetic состояние — запуск ndmc.

    function _renderNat(n) {
        const box = document.getElementById('gv-nat');
        if (!box) return;
        box.hidden = !(n && n.supported);
        if (box.hidden) return;
        const t = document.getElementById('gv-nat-toggle');
        if (t) t.checked = !!n.enabled;
        const st = document.getElementById('gv-nat-state');
        if (st) {
            const parts = [];
            if (n.software) parts.push(_tr('geneva.nat.software'));
            if (n.hardware) parts.push(_tr('geneva.nat.hardware'));
            st.textContent = ' — ' + (parts.length ? parts.join(', ') : _tr('geneva.nat.off'));
        }
    }

    async function _loadNat() {
        try {
            _renderNat(await API.get('/api/geneva/nat-offload'));
        } catch (e) {
            _renderNat(null);
        }
    }

    async function _natToggle(on) {
        const t = document.getElementById('gv-nat-toggle');
        const ok = await Confirm.show(_tr('geneva.nat.confirm_title'),
            esc(_tr(on ? 'geneva.nat.confirm_on' : 'geneva.nat.confirm_off')),
            { confirmLabel: _tr(on ? 'geneva.nat.turn_on' : 'geneva.nat.turn_off') });
        if (!ok) {
            if (t) t.checked = !on;
            return;
        }
        if (t) t.disabled = true;
        try {
            const res = await API.post('/api/geneva/nat-offload',
                { enabled: on, confirm: true }, { timeout: 60000 });
            _renderNat(res);
            Toast.success(_tr(on ? 'geneva.nat.done_on' : 'geneva.nat.done_off'));
        } catch (e) {
            Toast.error(errText(e));
            await _loadNat();
        } finally {
            if (t) t.disabled = false;
            _refresh();
        }
    }

    async function _autoReset(key) {
        try {
            await API.post('/api/geneva/auto/reset', { key });
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
    }

    /* ───────── рабочие стратегии (вкладка «Стратегии») ───────── */

    async function _loadFound() {
        const box = document.getElementById('gv-found');
        if (!box) return;
        try {
            _renderFound(await API.get('/api/geneva/found'));
        } catch (e) {
            box.innerHTML = `<div class="text-error">${esc(errText(e))}</div>`;
        }
    }

    const FOUND_CHIPS = 8;

    function _renderFound(res) {
        const box = document.getElementById('gv-found');
        if (!box || !res) return;
        const items = res.items || [];
        if (!items.length) {
            box.innerHTML = `<div class="text-muted">${esc(_tr('geneva.found.empty'))}</div>`;
            return;
        }
        box.innerHTML = items.map((r, i) => {
            const names = (r.services || []).map(x => x.name);
            const chips = names.slice(0, FOUND_CHIPS).map(n =>
                `<span class="badge badge-ghost">${esc(n)}</span>`).join(' ');
            const more = names.length > FOUND_CHIPS
                ? ` <span class="text-muted">${esc(_tr('geneva.found.more', { n: names.length - FOUND_CHIPS }))}</span>` : '';
            const targets = (r.targets || []).length
                ? `<div class="text-muted">${esc(_tr('geneva.found.search', { targets: r.targets.slice(0, 6).join(', ') }))}</div>` : '';
            const badges = [];
            if (r.auto) badges.push(`<span class="badge badge-success">${esc(_tr('geneva.found.auto', { n: names.length }))}</span>`);
            if (r.degraded) badges.push(`<span class="badge badge-warning">${esc(_tr('geneva.found.degraded', { n: r.degraded }))}</span>`);
            if ((r.targets || []).length) badges.push(`<span class="badge badge-info">${esc(_tr('geneva.found.manual'))}</span>`);
            if (r.working) badges.push(`<span class="badge badge-accent">${esc(_tr('geneva.found.working'))}</span>`);
            if (r.imported) badges.push(`<span class="badge badge-ghost">${esc(_tr('geneva.found.imported'))}</span>`);
            const when = r.last ? `<span class="text-muted">${esc(_tr('geneva.found.last', { when: fmtDate(r.last) }))}</span>` : '';
            const fit = r.fitness !== null && r.fitness !== undefined
                ? `<span class="text-muted">${esc(_tr('geneva.found.fitness', { f: Math.round(r.fitness) }))}</span>` : '';
            const use = res.auto_enabled || r.working ? '' :
                `<button class="btn btn-ghost btn-sm" data-use="${esc(r.strategy)}">${esc(_tr('geneva.found.use'))}</button>`;
            return `<div class="gv-found-row">
                <div class="gv-found-head">${badges.join(' ')} ${fit} ${when}</div>
                <div class="gv-mono gv-found-strategy">${esc(r.strategy)}</div>
                ${chips ? `<div class="gv-found-chips">${chips}${more}</div>` : ''}
                ${targets}
                <div class="gv-actions">
                    <button class="btn btn-ghost btn-sm" data-copy="${i}">${esc(_tr('geneva.found.copy'))}</button>
                    ${use}
                    ${r.imported ? `<button class="btn btn-ghost btn-sm" data-forget="${i}">${esc(_tr('geneva.found.forget'))}</button>` : ''}
                </div>
            </div>`;
        }).join('');
        box.dataset.strategies = JSON.stringify(items.map(r => r.strategy));
    }

    async function _exportFound() {
        try {
            const doc = await API.get('/api/geneva/found/export');
            const data = typeof doc === 'string' ? doc : JSON.stringify(doc, null, 1);
            const blob = new Blob([data], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'geneva-strategies.json';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
        } catch (e) {
            Toast.error(errText(e));
        }
    }

    async function _importFound(file) {
        if (!file) return;
        if (file.size > 512 * 1024) {
            Toast.error(_tr('geneva.found.import_big'));
            return;
        }
        try {
            const text = await file.text();
            let data = text;
            try { data = JSON.parse(text); } catch (e) { data = text; }
            const res = await API.post('/api/geneva/found/import', { data });
            Toast.success(_tr('geneva.found.imported_n', { n: res.accepted, added: res.added }));
            if ((res.errors || []).length) Toast.info(res.errors.slice(0, 3).join('; '));
        } catch (e) {
            Toast.error(errText(e));
        }
        _loadFound();
    }

    async function _forgetImported(i) {
        const box = document.getElementById('gv-found');
        let list = [];
        try { list = JSON.parse((box && box.dataset.strategies) || '[]'); } catch (e) { list = []; }
        const strategy = list[Number(i)];
        if (!strategy) return;
        try {
            await API.post('/api/geneva/found/forget', { strategy });
        } catch (e) {
            Toast.error(errText(e));
        }
        _loadFound();
    }

    function _copyFound(i) {
        const box = document.getElementById('gv-found');
        let list = [];
        try { list = JSON.parse((box && box.dataset.strategies) || '[]'); } catch (e) { list = []; }
        const text = list[Number(i)];
        if (!text) return;
        if (typeof Clipboard !== 'undefined' && Clipboard.copyWithToast) {
            Clipboard.copyWithToast(text);
        } else if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => Toast.success(_tr('geneva.found.copied')));
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
                найдено ${r.working_count} — <a href="#scan?tab=catalog">продолжить</a></div>`);
        }
        const s = ge.search || {};
        const geLines = [
            `<div>${!ge.installed ? 'Не установлен' : (ge.running ? 'Работает' : 'Остановлен')}</div>`,
            `<div class="text-muted gv-ellipsis" title="${esc(ge.strategy)}">Стратегия: ${ge.strategy ? `<span class="gv-mono">${esc(ge.strategy)}</span>` : 'не выбрана'}</div>`,
            `<div class="text-muted">Автозапуск: ${ge.autostart ? 'да' : 'нет'}</div>`,
        ];
        if (s.running) {
            geLines.push(`<div class="text-muted">Идёт подбор: ${s.kind === 'evolve' ? `поколение ${s.generation} из ${s.generations}` : 'проверка стратегий'} — <a href="#scan?tab=geneva">открыть</a></div>`);
        } else if (s.can_resume) {
            geLines.push(`<div class="text-muted">Подбор для ${esc(s.target)} прерван — <a href="#scan?tab=geneva">продолжить</a></div>`);
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
            if (res.warning) Toast.warning(res.warning);
            else if (res.started) Toast.success(`Обход идёт через ${name}`);
            else Toast.info(`${name} выбран движком, но не запущен — запустите его, когда будет стратегия`);
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
        const rel = d.release || {};
        const update = rel.has_update
            ? `<button class="btn btn-primary btn-sm" data-action="install">Обновить до ${esc(rel.latest)}</button>`
            : '';
        el.innerHTML = `<div class="text-muted gv-row" style="font-size:12px;margin-bottom:6px;">
            <span>geneva ${esc(d.version)} · ${esc(d.arch)} · ${esc(d.binary)}</span>
            ${update}</div>
            ${d.hint ? `<div class="text-error" style="font-size:12px;">${esc(d.hint)}</div>` : ''}`;
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
                выберите его в разделе <a href="#bypass">«Движок обхода»</a> — nfqws2 остановится.</div>` : ''}
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
            startBtn.title = active !== 'geneva' ? 'Сначала выберите geneva_c в разделе «Движок обхода»' : '';
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
            const started = res.ready ? 'запущен' : 'запущен, правила ставятся';
            Toast.success(action === 'start' ? 'geneva ' + started
                        : action === 'restart' ? 'geneva перезапущен' + (res.ready ? '' : ', правила ставятся')
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
            if (res.restart_needed) {
                const ok = await Confirm.show('Перезапустить geneva?',
                    'Движок работает на прежней версии — новая заработает после перезапуска.',
                    { confirmLabel: 'Перезапустить' });
                if (ok) await _engineAction('restart');
            }
        } catch (e) {
            Toast.error(errText(e));
        }
        _refresh();
        _loadLibrary();
    }

    /* ───────── подбор ───────── */

    const SIZES = { quick: [20, 8], normal: [30, 15], deep: [60, 30] };

    function _toggleCustomSize() {
        const sel = document.getElementById('gv-size');
        if (!sel) return;
        const v = sel.value;
        document.querySelectorAll('.gv-custom-size').forEach(el => el.classList.toggle('hidden', v !== 'custom'));
    }

    function _searchParams() {
        const val = (id, dflt) => { const el = document.getElementById(id); return el ? el.value : dflt; };
        const size = val('gv-size', 'normal');
        let [population, generations] = SIZES[size] || [
            parseInt(val('gv-population'), 10) || 30,
            parseInt(val('gv-generations'), 10) || 15];
        const pause = document.getElementById('gv-pause');
        return {
            host: (val('gv-host', '') || '').trim(),
            probe: val('gv-probe', 'tls'),
            population, generations,
            workers: parseInt(val('gv-workers'), 10) || 1,
            pause_bypass: pause ? !!pause.checked : true,
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
        if (!_formFilled && p.host && document.getElementById('gv-host')) {
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
        const country = (document.getElementById('gv-lib-country') || {}).value || '';
        const test = (document.getElementById('gv-lib-test') || {}).value || '';
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
                    <td style="white-space:nowrap;">${esc(i.rate)}%</td>
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
        const libHost = document.getElementById('gv-lib-host');
        if (libHost && libHost.value.trim()) params.host = libHost.value.trim();
        if (!params.host) {
            Toast.error('Укажите заблокированный сайт');
            return;
        }
        delete params.population;
        delete params.generations;
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
            const libHost = document.getElementById('gv-lib-host');
            if (libHost && !libHost.value && s.host) libHost.value = s.host;
            const pause = document.getElementById('gv-pause');
            if (pause && s.pause_bypass === false) pause.checked = false;
            _settingsFilled = true;
        } catch (_) { /* форма останется с умолчаниями */ }
    }

    async function _saveSettings() {
        const val = id => (document.getElementById(id) || {}).value;
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
        if (t.dataset.autoReset) return _autoReset(t.dataset.autoReset);
        if (t.dataset.copy !== undefined) return _copyFound(t.dataset.copy);
        if (t.dataset.forget !== undefined) return _forgetImported(t.dataset.forget);
        if (t.dataset.action === 'found-export') return _exportFound();
        if (t.dataset.action === 'found-import') {
            const f = document.getElementById('gv-found-file');
            if (f) f.click();
            return;
        }
        if (t.dataset.action === 'install') return _install();
        if (t.dataset.use) return _setStrategy(t.dataset.use, 'search');
        if (t.dataset.useLib) return _setStrategy(t.dataset.useLib, 'library');
    }

    return { render, destroy };
})();
