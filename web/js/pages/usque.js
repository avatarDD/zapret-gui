/**
 * usque.js — Страница управления WARP/MASQUE (usque).
 *
 * Показывает статус туннеля, список конфигов, управление запуском.
 */

const UsquePage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    let _visibilityHandler = null;
    let _inFlight = false;
    let _settingsLoaded = false;
    const _state = { installed: false, configs: [] };
    // Какие туннели раскрыты. Таблицу пересобирает не каждый тик, а
    // только изменение данных, но без этого набора раскрытая панель
    // «Подробнее» захлопывалась бы на любой пересборке.
    const _expanded = new Set();
    let _debugOn = false;

    // HTML панелей «Подробнее», отрисованный в прошлый раз. Нужен, чтобы
    // при пересборке таблицы вернуть раскрытую панель сразу с прежним
    // содержимым, а не с плашкой «Загрузка…» на время запроса.
    const _detailsHtml = new Map();   // имя профиля → HTML

    /**
     * Записать HTML только если он реально изменился.
     *
     * Опрос идёт раз в POLL_MS, а состояние туннеля меняется редко — без
     * этой проверки каждый тик переписывал innerHTML тем же самым
     * содержимым. На такой записи браузер сносит и строит заново всё
     * поддерево: таблица моргает, ховер и выделение текста слетают, а
     * раскрытая панель успевает схлопнуться и разъехаться обратно.
     */
    function _paint(el, html) {
        if (el.__usqLastHtml === html) return false;
        el.innerHTML = html;
        el.__usqLastHtml = html;
        return true;
    }

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>${_t('warp_masque')}${typeof Help !== 'undefined' ? Help.button('usque') : ''}</h1>
                <span class="page-subtitle">Бесплатный Cloudflare WARP по протоколу MASQUE
                    (HTTP/3 поверх QUIC, порт 443) — трафик выглядит как обычный HTTPS</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">С чего начать</div>
                    <div class="card-body">
                        <ol id="usque-steps" class="usque-steps">
                            <li data-step="install"><span class="usque-step-mark">•</span>
                                <span class="usque-step-text">Установить бинарник usque</span></li>
                            <li data-step="register"><span class="usque-step-mark">•</span>
                                <span class="usque-step-text">Зарегистрировать WARP-сессию —
                                    аккаунт создаётся бесплатно, без логина и оплаты</span></li>
                            <li data-step="start"><span class="usque-step-mark">•</span>
                                <span class="usque-step-text">Запустить туннель — появится
                                    сетевой интерфейс <code>usque0</code></span></li>
                            <li data-step="route"><span class="usque-step-mark">•</span>
                                <span class="usque-step-text">Направить нужный трафик в туннель на
                                    странице <a href="#routing">Маршрутизация</a>: сам по себе
                                    поднятый туннель ничего не перенаправляет</span></li>
                        </ol>
                    </div>
                </div>
            </div>

            <div class="card-grid" id="usque-env-card">
                <div class="card">
                    <div class="card-title">Окружение</div>
                    <div class="card-body" id="usque-env">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid" id="usque-configs-card">
                <div class="card">
                    <div class="card-title">Туннели</div>
                    <div class="card-body" id="usque-configs">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Действия</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="usque-btn-register">Зарегистрировать WARP</button>
                        <button class="btn" id="usque-btn-import">Импортировать конфиг</button>
                        <button class="btn" id="usque-btn-refresh">Обновить</button>
                        <div class="form-hint" style="margin-top:8px;">
                            Регистрация создаёт профиль с ключами вашей WARP-сессии
                            в <code>/opt/etc/zapret-gui/usque/</code>. Можно завести несколько
                            профилей, но одновременно обычно нужен один.
                        </div>
                        <div class="form-hint" style="margin-top:6px;">
                            <strong>Конфиг AmneziaWG сюда не подойдёт.</strong> usque —
                            клиент MASQUE (HTTP/3), а не WireGuard: у них разные
                            протоколы и разные ключи (X25519 против ECDSA P-256),
                            поэтому пересобрать <code>.conf</code> в сессию usque нельзя.
                            Импорт принимает только готовый <code>config.json</code>
                            самого usque — например, с другого устройства.
                        </div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Настройки</div>
                    <div class="card-body" id="usque-settings">Загрузка...</div>
                </div>
            </div>
        `;

        // MR-69: addEventListener вместо onclick
        document.getElementById("usque-btn-register").addEventListener("click", _register);
        document.getElementById("usque-btn-import").addEventListener("click", _import);
        document.getElementById("usque-btn-refresh").addEventListener("click", _refresh);

        // MR-90: Отслеживание видимости страницы для управления опросом
        _visibilityHandler = () => {
            if (document.hidden) _stopPoll();
            else _startPoll();
        };
        document.addEventListener("visibilitychange", _visibilityHandler);

        await _refresh();
        _startPoll();
    }

    function destroy() {
        _stopPoll();
        if (_visibilityHandler) {
            document.removeEventListener("visibilitychange", _visibilityHandler);
            _visibilityHandler = null;
        }
    }

    async function _refresh() {
        // MR-90: in-flight guard + document.hidden check
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            await Promise.all([_loadEnv(), _loadConfigs()]);
            // Настройки не поллим: форма перерисовалась бы под курсором
            // и затирала бы недовведённое значение. Грузим один раз.
            if (!_settingsLoaded) await _loadSettings();
            _renderSteps();
        } finally {
            _inFlight = false;
        }
    }

    /** Отметить пройденные шаги по фактическому состоянию. */
    function _renderSteps() {
        const done = {
            install: _state.installed,
            register: _state.configs.length > 0,
            start: _state.configs.some(c => c.active),
            route: false,   // знает только страница маршрутизации
        };
        document.querySelectorAll("#usque-steps li").forEach(li => {
            const step = li.getAttribute("data-step");
            const mark = li.querySelector(".usque-step-mark");
            if (!mark) return;
            if (done[step]) {
                mark.textContent = "✓";
                li.classList.add("usque-step-done");
            } else {
                mark.textContent = "•";
                li.classList.remove("usque-step-done");
            }
        });
    }

    async function _loadEnv() {
        try {
            const env = await API.get("/api/usque/environment");
            _state.installed = !!env.installed;
            const el = document.getElementById("usque-env");
            if (!el) return;
            const tunOk = !!(env.tun && env.tun.available);
            if (env.installed) {
                _paint(el, `
                    <div class="status-row">
                        <span class="status-dot status-ok"></span>
                        <span>Установлен: <strong>${esc(env.version || "?")}</strong></span>
                    </div>
                    <div class="detail-row">Бинарник: <code>${esc((env.binary && env.binary.path) || "")}</code></div>
                    <div class="detail-row">Архитектура: <code>${esc(env.arch || "?")}</code></div>
                    <div class="detail-row">
                        Поддержка TUN:
                        ${tunOk
                            ? '<span class="status-dot status-ok"></span> есть'
                            : '<span class="status-dot status-error"></span> не найдена'}
                    </div>
                    ${tunOk ? '' : `<div class="form-hint">
                        Без устройства <code>/dev/net/tun</code> туннель не поднимется.
                        На Keenetic модуль обычно даёт пакет <code>kmod-tun</code>.
                    </div>`}
                    <div style="margin-top:10px;">
                        <a class="btn btn-sm" href="#usque-setup">Установка и обновление</a>
                    </div>
                `);
            } else {
                const changed = _paint(el, `
                    <div class="status-row">
                        <span class="status-dot status-error"></span>
                        <span>Не установлен</span>
                    </div>
                    <div class="form-hint" style="margin-top:6px;">
                        usque — это клиент Cloudflare WARP. Бинарник скачивается
                        с GitHub-релизов проекта usque-keenetic, целостность
                        проверяется по SHA256.
                    </div>
                    <button class="btn btn-primary btn-sm" id="usque-install-btn" style="margin-top:8px;">
                        Установить usque
                    </button>
                `);
                // Слушатель вешаем только на свежесозданную кнопку: если
                // разметку не переписывали, старая кнопка со своим
                // обработчиком на месте, и повтор дал бы двойной запуск.
                if (changed) {
                    document.getElementById("usque-install-btn")
                        ?.addEventListener("click", install);
                }
            }
        } catch (e) {
            const el = document.getElementById("usque-env");
            if (el) _paint(el, `<div class="text-error">Ошибка: ${esc(String(e))}</div>`);
        }
    }

    async function _loadConfigs() {
        try {
            const data = await API.get("/api/usque/configs");
            const el = document.getElementById("usque-configs");
            if (!el) return;
            const configs = data.configs || [];
            _state.configs = configs;
            if (!configs.length) {
                _paint(el, `
                    <p class="text-muted">Туннелей пока нет.</p>
                    <div class="form-hint">
                        Нажмите «Зарегистрировать WARP» ниже — GUI создаст бесплатную
                        WARP-сессию у Cloudflare и сохранит её как профиль.
                        Ничего вводить не нужно, только имя профиля.
                    </div>`);
                return;
            }
            // colgroup обязателен: у .table задан table-layout: fixed, и без
            // явных ширин колонка «Действия» получала те же 25%, что и
            // остальные, — кнопки в неё не влезали и переносились.
            let html = '<table class="table">'
                + '<colgroup><col style="width:26%"><col style="width:20%">'
                + '<col style="width:20%"><col style="width:34%"></colgroup>'
                + '<thead><tr>';
            html += '<th>Профиль</th><th>Интерфейс</th><th>Статус</th><th>Действия</th>';
            html += '</tr></thead><tbody>';
            for (const c of configs) {
                const statusCls = c.active ? "status-ok" : "status-off";
                const statusText = c.active ? "Работает" : "Остановлен";
                const toggleBtn = c.active
                    ? `<button class="btn btn-danger btn-sm action-stop" data-name="${esc(c.name)}">Стоп</button>`
                    : `<button class="btn btn-primary btn-sm action-start" data-name="${esc(c.name)}">Старт</button>`;
                // Имя закрепляется за профилем при первом запуске и дальше
                // не меняется. Прочерк — у профиля, который ещё ни разу не
                // поднимали: это норма, а не ошибка.
                const ifaceCell = c.iface
                    ? `<code>${esc(c.iface)}</code>`
                    : '<span class="text-muted" title="Имя закрепится при первом запуске">—</span>';
                html += `<tr>
                    <td>${esc(c.name)}</td>
                    <td>${ifaceCell}</td>
                    <td><span class="status-dot ${statusCls}"></span> ${statusText}</td>
                    <td><div class="usque-actions">${toggleBtn}
                        <button class="btn btn-sm action-details" data-name="${esc(c.name)}">Подробнее</button>
                        <button class="btn btn-sm action-remove" data-name="${esc(c.name)}">Удалить</button>
                    </div></td>
                </tr>
                <tr class="usque-details-row" data-for="${esc(c.name)}" style="display:none;">
                    <td colspan="4">
                        <div class="usque-details" data-for="${esc(c.name)}">Загрузка…</div>
                        <div class="usque-log-box" data-for="${esc(c.name)}"></div>
                    </td>
                </tr>`;
            }
            html += '</tbody></table>';
            if (configs.some(c => c.active)) {
                html += `<div class="form-hint" style="margin-top:8px;">
                    Туннель поднят, но трафик в него пойдёт только после правила на странице
                    <a href="#routing">Маршрутизация</a> — выберите там метод
                    <code>warp:${esc(configs.find(c => c.active).iface || 'usque0')}</code>.
                </div>`;
            }
            // Таблицу трогаем, только когда она реально изменилась —
            // иначе кнопки, ховер и раскрытые панели пересоздавались бы
            // каждые POLL_MS (это и есть «моргание» страницы).
            const rebuilt = _paint(el, html);

            // Профили, исчезнувшие из списка, из набора раскрытых тоже
            // убираем — иначе _renderDetails каждый тик искал бы строку,
            // которой в таблице уже нет.
            for (const name of Array.from(_expanded)) {
                if (!configs.some(c => c.name === name)) {
                    _expanded.delete(name);
                    _detailsHtml.delete(name);
                }
            }

            if (rebuilt) {
                // MR-69: addEventListener вместо onclick. Вешаем только на
                // свежую разметку — на нетронутой обработчики уже стоят.
                el.querySelectorAll(".action-details").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        _toggleDetails(e.currentTarget.getAttribute("data-name"));
                    });
                });
                el.querySelectorAll(".action-stop").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        stop(e.currentTarget.getAttribute("data-name"));
                    });
                });
                el.querySelectorAll(".action-start").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        start(e.currentTarget.getAttribute("data-name"));
                    });
                });
                el.querySelectorAll(".action-remove").forEach(btn => {
                    btn.addEventListener("click", (e) => {
                        remove(e.currentTarget.getAttribute("data-name"));
                    });
                });
            }

            // Раскрытые панели: сначала мгновенно возвращаем прошлое
            // содержимое (чтобы после пересборки не мигала «Загрузка…»),
            // затем обновляем его запросом.
            for (const name of _expanded) {
                if (rebuilt) _restoreDetails(name);
                _renderDetails(name);
            }
        } catch (e) {
            const el = document.getElementById("usque-configs");
            if (el) _paint(el, `<div class="text-error">Ошибка: ${esc(String(e))}</div>`);
        }
    }

    /** Вернуть раскрытой панели её прошлое содержимое после пересборки. */
    function _restoreDetails(name) {
        const row = document.querySelector(
            `.usque-details-row[data-for="${CSS.escape(name)}"]`);
        if (!row) return;
        row.style.display = "";
        const box = row.querySelector(".usque-details");
        const cached = _detailsHtml.get(name);
        if (box && cached) {
            box.innerHTML = cached;
            box.__usqLastHtml = cached;
            _bindDetailActions(box, name);
        }
    }

    function _bindDetailActions(box, name) {
        box.querySelector(".action-log")?.addEventListener("click", () => {
            _loadLog(name);
        });
    }

    /**
     * Раскрыть/свернуть подробности туннеля.
     *
     * `diagnostic` — хвост stderr самого usque. Раньше API его отдавал, но
     * UI нигде не показывал, и пользователь при неудачном старте видел
     * только «Ошибка запуска» без причины.
     */
    function _toggleDetails(name) {
        if (_expanded.has(name)) {
            _expanded.delete(name);
            const row = document.querySelector(
                `.usque-details-row[data-for="${CSS.escape(name)}"]`);
            if (row) row.style.display = "none";
            return;
        }
        _expanded.add(name);
        _renderDetails(name);
    }

    async function _renderDetails(name) {
        const row = document.querySelector(
            `.usque-details-row[data-for="${CSS.escape(name)}"]`);
        if (!row) return;
        row.style.display = "";
        const box = row.querySelector(".usque-details");
        try {
            const st = await API.get(
                `/api/usque/configs/${encodeURIComponent(name)}/status`);
            // Панель могли свернуть, пока шёл запрос.
            if (!_expanded.has(name)) return;
            if (st && st.ok === false) {
                _setDetails(box, name,
                    `<div class="text-error">${esc(st.error || "Ошибка")}</div>`);
                return;
            }
            const diag = (st.diagnostic || "").trim();
            _setDetails(box, name, `
                <div class="detail-row">Процесс: ${st.running
                    ? '<span class="status-dot status-ok"></span> запущен'
                    : '<span class="status-dot status-off"></span> не запущен'}
                    ${st.pid ? ` (PID <code>${esc(String(st.pid))}</code>)` : ""}</div>
                <div class="detail-row">Интерфейс <code>${esc(st.iface || "—")}</code>:
                    ${st.iface_exists ? "существует" : "отсутствует"}${st.iface_exists
                        ? (st.link_up
                            ? ", link поднят"
                            : ', <span class="text-error">link не поднят</span>')
                        : ""}</div>
                ${st.iface_exists && !st.link_up
                    ? `<div class="form-hint">Интерфейс есть, но не поднят — трафик через
                           него не пойдёт. Обычно это значит, что не удалось назначить
                           адрес из сессии (нет прав или занят другим интерфейсом).</div>`
                    : ""}
                ${diag
                    ? `<div style="margin-top:8px;">
                           <div class="form-label">Последние сообщения usque</div>
                           <pre class="usque-diagnostic">${esc(diag)}</pre>
                           <div class="form-hint">Это вывод самого usque — по нему видно,
                               почему туннель не поднялся (нет сети, отвергнута сессия,
                               занят интерфейс).</div>
                       </div>`
                    : `<div class="form-hint" style="margin-top:8px;">
                           Сообщений от usque нет. Если туннель не поднимается —
                           проверьте доступ в интернет и переключите транспорт на
                           «Restricted» в настройках ниже.
                       </div>`}
                <div style="margin-top:8px;">
                    <button class="btn btn-sm action-log" data-name="${esc(name)}">Полный лог</button>
                </div>
            `);
        } catch (e) {
            _setDetails(box, name,
                `<div class="text-error">${esc(String(e))}</div>`);
        }
    }

    /**
     * Обновить панель «Подробнее», не трогая её при неизменном содержимом.
     *
     * Панель перечитывается на каждом тике опроса, а меняется в ней разве
     * что PID или хвост лога. Без этой проверки innerHTML переписывался
     * каждые POLL_MS, и раскрытая панель заметно дёргалась. Блок с полным
     * логом лежит СНАРУЖИ (соседним узлом) — иначе обновление подробностей
     * стирало бы уже открытый лог.
     */
    function _setDetails(box, name, html) {
        if (!box) return;
        if (_paint(box, html)) {
            _detailsHtml.set(name, html);
            _bindDetailActions(box, name);
        }
    }

    async function _loadLog(name) {
        const box = document.querySelector(
            `.usque-log-box[data-for="${CSS.escape(name)}"]`);
        if (!box) return;
        box.innerHTML = '<div class="form-hint">Загрузка лога…</div>';
        try {
            const r = await API.get(
                `/api/usque/configs/${encodeURIComponent(name)}/log?lines=300`);
            if (r && r.ok === false) {
                box.innerHTML = `<div class="text-error">${esc(r.error || "Ошибка")}</div>`;
                return;
            }
            const text = (r.log || "").trim();
            if (!text) {
                box.innerHTML = `<div class="form-hint">
                    ${esc(r.message || "Буфер пуст — usque ничего не выводил.")}
                </div>`;
                return;
            }
            box.innerHTML = `
                <pre class="usque-diagnostic">${esc(text)}</pre>
                <div class="form-hint">
                    Строк в буфере: ${r.captured || 0} из ${r.capacity || "?"}.
                    ${r.debug ? "Режим отладки включён."
                              : "Включите режим отладки в настройках, чтобы буфер хранил больше строк."}
                </div>`;
        } catch (e) {
            box.innerHTML = `<div class="text-error">${esc(String(e))}</div>`;
        }
    }

    function _showPromptModal(title, defaultValue, placeholder, callback) {
        const old = document.getElementById("prompt-modal-overlay");
        if (old) old.remove();

        const overlay = document.createElement("div");
        overlay.id = "prompt-modal-overlay";
        overlay.className = "modal-overlay";
        overlay.style.position = "fixed";
        overlay.style.inset = "0";
        overlay.style.backgroundColor = "rgba(0, 0, 0, 0.5)";
        overlay.style.display = "flex";
        overlay.style.alignItems = "center";
        overlay.style.justifyContent = "center";
        overlay.style.zIndex = "1000";

        const content = document.createElement("div");
        content.className = "modal-content";
        content.style.backgroundColor = "var(--bg-card, #1a1d28)";
        content.style.padding = "24px";
        content.style.borderRadius = "8px";
        content.style.width = "90%";
        content.style.maxWidth = "400px";
        content.style.boxShadow = "0 4px 12px rgba(0,0,0,0.3)";

        content.innerHTML = `
            <div style="font-weight:bold; font-size:1.1rem; margin-bottom:12px; color:var(--text-main, #e1e4ea);">${esc(title)}</div>
            <div style="font-size:12px; color:var(--text-muted, #8b90a0); margin-bottom:10px;">
                Имя профиля — только для вас, оно станет именем файла сессии.
                Например <code>warp-default</code> или <code>warp-backup</code>.
                Латиница, цифры, <code>_</code> и <code>-</code>.
            </div>
            <div style="margin-bottom:16px;">
                <input type="text" id="prompt-modal-input" class="form-input"
                       value="${esc(defaultValue)}" placeholder="${esc(placeholder)}"
                       style="width:100%; box-sizing:border-box; padding:8px; border-radius:4px; border:1px solid var(--border, #2d313f); background:var(--bg-input, #0f111a); color:var(--text-main, #e1e4ea);" />
                <div id="prompt-modal-error" style="color:var(--text-error, #ff5370); font-size:0.85rem; margin-top:4px; display:none;"></div>
            </div>
            <div style="margin-bottom:16px;">
                <label class="form-label" for="prompt-modal-transport">Регистрировать через</label>
                <select id="prompt-modal-transport" class="form-input"
                        style="width:100%; box-sizing:border-box; padding:8px; border-radius:4px; border:1px solid var(--border, #2d313f); background:var(--bg-input, #0f111a); color:var(--text-main, #e1e4ea);">
                    <option value="direct">Напрямую</option>
                </select>
                <div class="form-hint" style="margin-top:4px;">
                    Регистрация идёт на <code>api.cloudflareclient.com</code>.
                    Если провайдер режет его (ошибка «TLS handshake timeout»),
                    выберите уже работающий обход — AWG-туннель или
                    sing-box/mihomo.
                </div>
            </div>
            <div style="display:flex; justify-content:flex-end; gap:8px;">
                <button class="btn" id="prompt-modal-cancel">Отмена</button>
                <button class="btn btn-primary" id="prompt-modal-ok">ОК</button>
            </div>
        `;

        overlay.appendChild(content);
        document.body.appendChild(overlay);

        // Список транспортов — тот же, что у «Качать через» на странице
        // установки (общий эндпоинт), поэтому здесь ничего своего не надо.
        const transportSel = document.getElementById("prompt-modal-transport");
        (async () => {
            try {
                const list = await TransportSelect.load();
                transportSel.innerHTML = TransportSelect.optionsHtml(list, "direct");
            } catch (_) { /* остаётся «Напрямую» */ }
        })();

        const input = document.getElementById("prompt-modal-input");
        const okBtn = document.getElementById("prompt-modal-ok");
        const cancelBtn = document.getElementById("prompt-modal-cancel");
        const errorDiv = document.getElementById("prompt-modal-error");

        input.focus();
        input.select();

        function submit() {
            const val = input.value.trim();
            // MR-100: валидация имени регулярным выражением (исключает path traversal)
            if (!/^[a-zA-Z0-9_-]{1,32}$/.test(val)) {
                errorDiv.textContent = "Только латиница, цифры, _ и - (1-32 симв.)";
                errorDiv.style.display = "block";
                return;
            }
            const transport = (transportSel && transportSel.value) || "direct";
            overlay.remove();
            callback(val, transport);
        }

        // MR-69: addEventListener вместо onclick
        okBtn.addEventListener("click", submit);
        cancelBtn.addEventListener("click", () => overlay.remove());
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                submit();
            } else if (e.key === "Escape") {
                overlay.remove();
            }
        });
        overlay.onclick = (e) => {
            if (e.target === overlay) overlay.remove();
        };
    }

    async function _loadSettings() {
        const el = document.getElementById("usque-settings");
        if (!el) return;
        let s;
        try {
            const r = await API.get("/api/usque/settings");
            s = (r && r.settings) || {};
            try {
                const d = await API.get("/api/usque/debug");
                _debugOn = !!(d && d.enabled);
            } catch (_) { /* необязательно */ }
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
            return;
        }
        const wd = s.watchdog || {};
        const sel = (v, val) => (v === val ? " selected" : "");
        el.innerHTML = `
            <div class="form-group">
                <label class="form-label" style="display:flex; align-items:center; gap:8px;">
                    <input type="checkbox" id="usq-enabled" ${s.enabled ? "checked" : ""}>
                    Разрешить фоновое управление туннелем
                </label>
                <div class="form-hint">
                    Общий выключатель для автозапуска и watchdog. Кнопки «Старт»/«Стоп»
                    работают и без него — он нужен, только чтобы GUI трогал туннель сам.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" style="display:flex; align-items:center; gap:8px;">
                    <input type="checkbox" id="usq-autostart" ${s.autostart ? "checked" : ""}>
                    Поднимать туннель после перезагрузки роутера
                </label>
                <div class="form-hint">
                    Работает только вместе с галкой выше. Поднимаются все профили,
                    которые на момент загрузки не запущены.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="usq-transport">Транспорт</label>
                <select id="usq-transport" class="form-control">
                    <option value="performance"${sel(s.transport_profile, "performance")}>
                        Performance — HTTP/3 поверх QUIC (быстрее, по умолчанию)</option>
                    <option value="restricted"${sel(s.transport_profile, "restricted")}>
                        Restricted — HTTP/2 поверх TCP:443 (когда QUIC режут)</option>
                    <option value="auto"${sel(s.transport_profile, "auto")}>
                        Auto — сначала H3, при подтверждённом сбое одна попытка H2</option>
                </select>
                <div class="form-hint">
                    Многие провайдеры и мобильные операторы режут UDP/QUIC — тогда
                    Performance молча не поднимается. Признак: туннель не стартует,
                    а в «Подробнее» нет внятной ошибки. Лечится переключением
                    на Restricted.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="usq-sni">SNI для маскировки</label>
                <input type="text" id="usq-sni" class="form-control"
                       value="${esc(s.default_sni || "")}" placeholder="например: ozon.ru">
                <div class="form-hint">
                    Имя, которое видит DPI в TLS-рукопожатии. Пусто — не подменять.
                    Осмысленно указывать крупный сайт, к которому обращения не выглядят
                    подозрительно: <code>ozon.ru</code>, <code>www.google.com</code>.
                    Только доменное имя, без <code>https://</code> и путей.
                </div>
            </div>

            <hr style="border:none; border-top:1px solid var(--border); margin:16px 0;">

            <div class="form-group">
                <label class="form-label" style="display:flex; align-items:center; gap:8px;">
                    <input type="checkbox" id="usq-wd-enabled" ${wd.enabled ? "checked" : ""}>
                    Watchdog: перезапускать туннель, если он перестал отвечать
                </label>
                <div class="form-hint">
                    Раз в N секунд GUI пробует TCP-соединение через туннель. Три неудачи
                    подряд — перезапуск, затем пауза 2 минуты. Не чаще 6 перезапусков в час.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="usq-wd-interval">Интервал проверки, секунд</label>
                <input type="number" id="usq-wd-interval" class="form-control"
                       min="10" max="3600" value="${esc(String(wd.interval_sec || 60))}">
                <div class="form-hint">
                    По умолчанию 60. Меньше 10 не даст выставить: частые пробы
                    нагружают слабый роутер и ничего не улучшают.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label">Куда стучаться при проверке</label>
                <div style="display:flex; gap:8px;">
                    <input type="text" id="usq-wd-host" class="form-control" style="flex:2;"
                           value="${esc(wd.probe_host || "1.1.1.1")}" placeholder="1.1.1.1">
                    <input type="number" id="usq-wd-port" class="form-control" style="flex:1;"
                           min="1" max="65535" value="${esc(String(wd.probe_port || 443))}">
                </div>
                <div class="form-hint">
                    Адрес и порт, доступные снаружи. По умолчанию <code>1.1.1.1:443</code>.
                    Указывайте IP, а не домен: проба идёт через туннель напрямую,
                    без резолва.
                </div>
            </div>

            <hr style="border:none; border-top:1px solid var(--border); margin:16px 0;">

            <div class="form-group">
                <label class="form-label" style="display:flex; align-items:center; gap:8px;">
                    <input type="checkbox" id="usq-debug" ${_debugOn ? "checked" : ""}>
                    Режим отладки
                </label>
                <div class="form-hint">
                    Хранить длинный хвост вывода usque (500 строк вместо 40) —
                    он виден по кнопке «Лог» у туннеля. Нужен, когда туннель
                    поднимается, но через какое-то время отваливается: в
                    коротком буфере причина уже затирается. Новая глубина
                    применяется со следующего запуска туннеля.
                </div>
            </div>

            <button class="btn btn-primary" id="usq-save">Сохранить настройки</button>
        `;
        document.getElementById("usq-save").addEventListener("click", _saveSettings);
        _settingsLoaded = true;
    }

    async function _saveSettings() {
        const val = (id) => document.getElementById(id);
        const payload = {
            enabled: val("usq-enabled").checked,
            autostart: val("usq-autostart").checked,
            transport_profile: val("usq-transport").value,
            default_sni: val("usq-sni").value.trim(),
            watchdog: {
                enabled: val("usq-wd-enabled").checked,
                interval_sec: parseInt(val("usq-wd-interval").value, 10) || 60,
                probe_host: val("usq-wd-host").value.trim() || "1.1.1.1",
                probe_port: parseInt(val("usq-wd-port").value, 10) || 443,
            },
        };
        try {
            // Отладка живёт отдельной ручкой (её читают и менеджер, и
            // страница туннелей), поэтому сохраняем её первой.
            const dbg = document.getElementById("usq-debug").checked;
            if (dbg !== _debugOn) {
                await API.post("/api/usque/debug", { enabled: dbg });
                _debugOn = dbg;
            }
            const r = await API.post("/api/usque/settings", payload);
            if (r && r.ok) {
                Toast.success("Настройки сохранены");
                _settingsLoaded = false;
                await _loadSettings();
            } else {
                Toast.error((r && r.error) || "Не удалось сохранить");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _register() {
        // MR-100: Используем наш кастомный prompt-modal вместо native prompt()
        _showPromptModal("Новый WARP-профиль", "warp-default", "warp-default", async (name, transport) => {
            try {
                Toast.info(transport && transport !== "direct"
                    ? `Регистрируем сессию у Cloudflare через ${transport}…`
                    : "Регистрируем сессию у Cloudflare…");
                const res = await API.post("/api/usque/register", { name, transport });
                if (res.ok) {
                    Toast.success(_t("warp_registered"));
                    await _refresh();
                } else {
                    Toast.error(res.error || "Ошибка регистрации");
                }
            } catch (e) {
                Toast.error("Ошибка: " + e.message);
            }
        });
    }

    /** Импорт готового usque-конфига (config.json), НЕ AWG. */
    function _import() {
        const old = document.getElementById("usque-import-overlay");
        if (old) old.remove();
        const overlay = document.createElement("div");
        overlay.id = "usque-import-overlay";
        overlay.className = "modal-overlay";
        overlay.style.cssText = "position:fixed; inset:0; background:rgba(0,0,0,0.5);"
            + "display:flex; align-items:center; justify-content:center; z-index:1000;";
        overlay.innerHTML = `
            <div class="modal-content" style="background:var(--bg-card,#1a1d28); padding:24px;
                 border-radius:8px; width:92%; max-width:560px; max-height:85vh; overflow:auto;">
                <div style="font-weight:bold; font-size:1.1rem; margin-bottom:8px;">
                    Импорт конфига usque
                </div>
                <div class="form-hint" style="margin-bottom:12px;">
                    Вставьте содержимое <code>config.json</code> от usque — например,
                    с другого роутера или компьютера, где сессия уже
                    зарегистрирована. Файл <code>.conf</code> от AmneziaWG/WireGuard
                    не подойдёт: это другой протокол и другие ключи.
                </div>
                <div class="form-group">
                    <label class="form-label" for="usq-imp-name">Имя профиля</label>
                    <input type="text" id="usq-imp-name" class="form-control"
                           style="width:100%; box-sizing:border-box;"
                           value="warp-imported" placeholder="warp-imported">
                </div>
                <div class="form-group">
                    <label class="form-label" for="usq-imp-text">Содержимое config.json</label>
                    <textarea id="usq-imp-text" class="form-control" rows="10"
                              style="font-family:monospace; font-size:12px;
                                     width:100%; box-sizing:border-box; resize:vertical;"
                              placeholder='{ "private_key": "...", "access_token": "...", "id": "..." }'></textarea>
                    <div id="usq-imp-error" class="text-error" style="font-size:12px; margin-top:6px; display:none;"></div>
                </div>
                <div style="display:flex; justify-content:flex-end; gap:8px;">
                    <button class="btn" id="usq-imp-cancel">Отмена</button>
                    <button class="btn btn-primary" id="usq-imp-ok">Импортировать</button>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        overlay.addEventListener("click", (e) => {
            if (e.target === overlay) overlay.remove();
        });
        document.getElementById("usq-imp-cancel")
            .addEventListener("click", () => overlay.remove());
        document.getElementById("usq-imp-ok").addEventListener("click", async () => {
            const errEl = document.getElementById("usq-imp-error");
            const name = document.getElementById("usq-imp-name").value.trim();
            const text = document.getElementById("usq-imp-text").value;
            errEl.style.display = "none";
            if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
                errEl.textContent = "Имя: только латиница, цифры, _ и - (1-64)";
                errEl.style.display = "block";
                return;
            }
            try {
                const r = await API.post("/api/usque/configs/import", { name, text });
                if (r && r.ok) {
                    overlay.remove();
                    Toast.success(`Конфиг ${name} импортирован`);
                    await _refresh();
                } else {
                    errEl.textContent = (r && r.error) || "Не удалось импортировать";
                    errEl.style.display = "block";
                }
            } catch (e) {
                errEl.textContent = "Ошибка: " + e.message;
                errEl.style.display = "block";
            }
        });
        document.getElementById("usq-imp-text").focus();
    }

    async function start(name) {
        try {
            const res = await API.post(`/api/usque/configs/${encodeURIComponent(name)}/up`);
            if (res.ok) {
                Toast.success(`Туннель ${name} запущен`);
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка запуска");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function stop(name) {
        try {
            const res = await API.post(`/api/usque/configs/${encodeURIComponent(name)}/down`);
            if (res.ok) {
                Toast.success(`Туннель ${name} остановлен`);
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка остановки");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function remove(name) {
        if (!confirm(_t("delete_config_confirm", { name }))) return;
        try {
            const res = await API.post(`/api/usque/configs/${encodeURIComponent(name)}/remove`);
            if (res.ok) {
                Toast.success(`Конфиг ${name} удалён`);
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка удаления");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function install() {
        Toast.info("Установка usque...");
        try {
            // /install запускает установку в фоне и сразу отдаёт progress.
            // Поллим /install/status до завершения — иначе toast «установлен»
            // показывался бы до того, как opkg реально скачал и поставил пакет.
            const res = await API.post("/api/usque/install");
            if (!res.ok) {
                Toast.error(res.error || "Ошибка установки");
                return;
            }
            const started = Date.now();
            const MAX_MS = 120000;
            while (Date.now() - started < MAX_MS) {
                await new Promise(r => setTimeout(r, 1500));
                let st;
                try {
                    st = await API.get("/api/usque/install/status");
                } catch (_) { continue; }
                const p = (st && st.progress) || {};
                if (p.status === "done") {
                    Toast.success("usque установлен");
                    await _refresh();
                    return;
                }
                if (p.status === "error") {
                    Toast.error(p.message || "Ошибка установки");
                    await _refresh();
                    return;
                }
            }
            Toast.error("Установка не завершилась вовремя — проверьте статус");
            await _refresh();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    function _startPoll() {
        if (!_pollTimer) {
            _pollTimer = setInterval(_refresh, POLL_MS);
        }
    }

    function _stopPoll() {
        if (_pollTimer) {
            clearInterval(_pollTimer);
            _pollTimer = null;
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, start, stop, remove, install };
})();
