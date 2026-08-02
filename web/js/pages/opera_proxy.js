/**
 * opera_proxy.js — Страница управления Opera Proxy.
 *
 * Standalone Opera VPN: HTTP/SOCKS5 прокси через SurfEasy.
 * Zero-config: запустил → прокси работает.
 */

const OperaProxyPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    let _visibilityHandler = null;
    let _inFlight = false;
    // Форма настроек рисуется один раз. Раньше её перерисовывал каждый
    // тик опроса (3 с) — набранный текст и фокус улетали прямо во время
    // ввода, а «Сохранить» отправлял то, что успел вернуть сервер.
    let _configRendered = false;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Opera Proxy${typeof Help !== 'undefined' ? Help.button('opera') : ''}</h1>
                <span class="page-subtitle">Бесплатный HTTP/SOCKS5 прокси через SurfEasy VPN</span>
            </div>

            <div class="card-grid" id="opera-status-card">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="opera-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid" id="opera-detect-card">
                <div class="card">
                    <div class="card-title">Окружение</div>
                    <div class="card-body" id="opera-detect">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Настройки</div>
                    <div class="card-body" id="opera-config">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Действия</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="opera-btn-up">Запустить</button>
                        <button class="btn btn-danger" id="opera-btn-down">Остановить</button>
                        <button class="btn" id="opera-btn-refresh">Обновить</button>
                        <button class="btn" id="opera-btn-log">Лог</button>
                        <label style="display:inline-flex; align-items:center; gap:6px;
                                      margin-left:12px; font-size:12px; cursor:pointer;"
                               title="Хранить длинный хвост вывода opera-proxy (600 строк вместо 60)">
                            <input type="checkbox" id="opera-debug"> режим отладки
                        </label>
                        <div class="form-hint" style="margin-top:8px;">
                            Логи прокси видны по кнопке «Лог». Подробные строки
                            появятся, только если в настройках выбран
                            <strong>Verbosity = Debug (10)</strong> — уровень задаёт
                            сам opera-proxy, а режим отладки лишь увеличивает
                            хранимый хвост.
                        </div>
                        <div id="opera-log-box"></div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Использование</div>
                    <div class="card-body">
                        <p class="text-muted" style="font-size:12px;">
                            Opera Proxy создаёт HTTP прокси на <code id="opera-bind-display">127.0.0.1:18080</code>.
                            Настройте приложения использовать этот прокси.
                        </p>
                        <p class="text-muted" style="font-size:12px;">
                            Отдельным методом в «Маршрутизации» его выбрать нельзя:
                            там цель правила — сетевой интерфейс, а Opera Proxy
                            даёт только локальный порт. Чтобы заворачивать в неё
                            трафик роутера, подключите её как upstream внутрь
                            sing-box или mihomo — правило маршрутизации тогда
                            обычное, на TUN этого движка.
                        </p>

                        <div class="form-group" style="margin-top:12px;">
                            <label class="form-label" for="opera-chain-engine">Подключить в</label>
                            <div id="opera-chain-controls" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
                                <select id="opera-chain-engine" class="form-control" style="max-width:160px;">
                                    <option value="singbox">sing-box</option>
                                    <option value="mihomo">mihomo</option>
                                </select>
                                <select id="opera-chain-config" class="form-control" style="max-width:260px;">
                                    <option value="">Загрузка…</option>
                                </select>
                                <button class="btn btn-primary" id="opera-chain-btn">Добавить в конфиг</button>
                            </div>
                            <div class="form-hint" style="margin-top:6px;">
                                В конфиг добавится прокси с текущим bind и режимом
                                (HTTP или SOCKS5 — как выбрано в настройках выше),
                                плюс правило «<code>sec-tunnel.com</code> — напрямую»:
                                без него трафик самой Opera уходил бы в туннель по кругу.
                                Дальше в конфиге движка направьте на этот прокси нужные
                                домены — сам по себе он трафик не забирает.
                            </div>
                            <div id="opera-chain-result" style="margin-top:8px;"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // MR-69: addEventListener вместо onclick
        document.getElementById("opera-btn-up").addEventListener("click", _start);
        // До ответа детекта считаем, что бинарника нет: лучше на миг
        // недоступная кнопка, чем клик, который гарантированно провалится.
        _setStartEnabled(false);
        document.getElementById("opera-btn-log").addEventListener("click", _loadLog);
        document.getElementById("opera-debug").addEventListener("change", _setDebug);
        _loadDebugFlag();
        document.getElementById("opera-btn-down").addEventListener("click", _stop);
        document.getElementById("opera-btn-refresh").addEventListener("click", _refreshAll);
        document.getElementById("opera-chain-engine")
            .addEventListener("change", _renderChainConfigs);
        document.getElementById("opera-chain-btn")
            .addEventListener("click", _chainAttach);
        _loadChainTargets();

        _visibilityHandler = () => {
            if (document.hidden) _stopPoll();
            else _startPoll();
        };
        document.addEventListener("visibilitychange", _visibilityHandler);

        _configRendered = false;
        await _refresh();
        _startPoll();
    }

    function destroy() {
        _stopPoll();
        _configRendered = false;
        if (_visibilityHandler) {
            document.removeEventListener("visibilitychange", _visibilityHandler);
            _visibilityHandler = null;
        }
    }

    /** Кнопка «Обновить»: перечитать и перерисовать в том числе форму. */
    async function _refreshAll() {
        _configRendered = false;
        await _refresh();
    }

    /** Полное обновление — по кнопке и при открытии страницы. */
    async function _refresh() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            await Promise.all([_loadStatus(), _loadDetect(), _loadConfig()]);
        } finally {
            _inFlight = false;
        }
    }

    /**
     * Тик опроса — только статус.
     *
     * detect() и config по таймеру не дёргаем: detect на бэкенде
     * запускал `-list-countries`, а это регистрация устройства в API
     * SurfEasy — каждые 3 секунды.
     */
    async function _tick() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            await _loadStatus();
        } finally {
            _inFlight = false;
        }
    }

    async function _loadStatus() {
        try {
            const st = await API.get("/api/opera-proxy/status");
            const el = document.getElementById("opera-status");
            if (!el) return;
            // «Процесс жив» ≠ «прокси работает»: opera-proxy крутится и
            // не приняв конфигурацию от SurfEasy. Показываем оба факта.
            let cls = "status-off", text = "Остановлен";
            if (st.running) {
                const listening = st.listening !== false;
                cls = listening ? "status-ok" : "status-error";
                text = listening ? "Работает" : "Запущен, но порт не отвечает";
            }
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                    ${st.pid ? `<span class="text-muted">PID ${st.pid}</span>` : ""}
                    ${st.bind ? `<span class="text-muted">${esc(st.bind)}</span>` : ""}
                </div>
                ${st.running && st.listening === false ? `
                <div class="form-hint">Процесс жив, но соединение на
                    ${esc(st.bind || "")} не принимается — смотрите «Лог».</div>` : ""}
            `;
        } catch (e) {
            const el = document.getElementById("opera-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadDebugFlag() {
        try {
            const r = await API.get("/api/opera-proxy/debug");
            const el = document.getElementById("opera-debug");
            if (el) el.checked = !!(r && r.enabled);
        } catch (_) { /* необязательно */ }
    }

    async function _setDebug(e) {
        try {
            const r = await API.post("/api/opera-proxy/debug",
                                     { enabled: e.target.checked });
            if (r && r.ok) {
                Toast.success(r.note || "Сохранено");
            } else {
                Toast.error((r && r.error) || "Не удалось сохранить");
            }
        } catch (err) {
            Toast.error("Ошибка: " + err.message);
        }
    }

    async function _loadLog() {
        const box = document.getElementById("opera-log-box");
        if (!box) return;
        box.innerHTML = '<div class="form-hint">Загрузка лога…</div>';
        try {
            const r = await API.get("/api/opera-proxy/log?lines=300");
            const text = (r && r.log || "").trim();
            if (!text) {
                box.innerHTML = `<div class="form-hint">
                    Буфер пуст. Прокси либо не запускался в этом сеансе GUI,
                    либо ничего не вывел — при Verbosity = Silent (60) это норма.
                </div>`;
                return;
            }
            box.innerHTML = `
                <pre class="usque-diagnostic">${esc(text)}</pre>
                <div class="form-hint">Строк в буфере: ${r.captured || 0}.
                    ${r.debug ? "Режим отладки включён."
                              : "Включите режим отладки, чтобы буфер хранил больше строк."}
                </div>`;
        } catch (e) {
            box.innerHTML = `<div class="text-error">${esc(String(e))}</div>`;
        }
    }

    function _setStartEnabled(enabled) {
        const btn = document.getElementById("opera-btn-up");
        if (!btn) return;
        btn.disabled = !enabled;
        btn.title = enabled
            ? ""
            : "Сначала установите opera-proxy — кнопка ниже, в блоке «Окружение»";
    }

    async function _loadDetect() {
        try {
            const d = await API.get("/api/opera-proxy/detect");
            const el = document.getElementById("opera-detect");
            if (!el) return;
            // Без бинарника «Запустить» может только упасть — гасим кнопку
            // и объясняем причину прямо на ней.
            _setStartEnabled(!!d.installed);
            if (d.installed) {
                let html = `
                    <div class="status-row">
                        <span class="status-dot status-ok"></span>
                        <span>Установлен: <strong>${esc(d.version || "?")}</strong></span>
                    </div>
                    <div class="detail-row">Бинарник: <code>${esc(d.binary)}</code></div>
                `;
                html += _countriesHtml(d.countries || []);
                // Кнопка обновления нужна именно установленным: ставится
                // последний релиз апстрима, а раньше с этой страницы можно
                // было только установить «с нуля» — «Обновления» показывали
                // новую версию, а поставить её было нечем.
                html += `
                    <button class="btn btn-sm" id="opera-btn-update" style="margin-top:6px;"
                            title="Скачать последний релиз Alexey71/opera-proxy">
                        Обновить до последней версии
                    </button>`;
                el.innerHTML = html;
                _bindCountriesButton();
                document.getElementById("opera-btn-update")
                    ?.addEventListener("click", install);
            } else {
                el.innerHTML = `
                    <div class="status-row">
                        <span class="status-dot status-error"></span>
                        <span>Не установлен</span>
                    </div>
                    <button class="btn btn-primary btn-sm" id="opera-btn-install" style="margin-top:8px;">
                        Установить opera-proxy
                    </button>
                `;
                document.getElementById("opera-btn-install")?.addEventListener("click", install);
            }
        } catch (e) {
            const el = document.getElementById("opera-detect");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    /** Список стран: тянется отдельной кнопкой (это сетевой запрос). */
    function _countriesHtml(countries) {
        let html = '<div class="detail-row" id="opera-countries">Страны: ';
        if (countries.length) {
            html += countries.map(c =>
                `<span class="badge">${esc(c.code)}</span> ${esc(c.name)}`
            ).join(', ');
        } else {
            html += '<span class="text-muted">не запрашивались</span>';
        }
        html += `</div>
            <button class="btn btn-sm" id="opera-btn-countries" style="margin-top:6px;"
                    title="Запрос идёт в API SurfEasy и занимает несколько секунд">
                Обновить список стран
            </button>`;
        return html;
    }

    function _bindCountriesButton() {
        document.getElementById("opera-btn-countries")
            ?.addEventListener("click", _loadCountries);
    }

    async function _loadCountries() {
        const btn = document.getElementById("opera-btn-countries");
        const box = document.getElementById("opera-countries");
        if (btn) { btn.disabled = true; btn.textContent = "Запрос…"; }
        try {
            // Две регистрации в API SurfEasy — дефолтных 15с фронту мало.
            const r = await API.get("/api/opera-proxy/countries?refresh=1",
                                    { timeout: 45000 });
            const countries = (r && r.countries) || [];
            if (box) {
                box.innerHTML = "Страны: " + (countries.length
                    ? countries.map(c =>
                        `<span class="badge">${esc(c.code)}</span> ${esc(c.name)}`
                      ).join(', ')
                    : `<span class="text-muted">${esc(r && r.error
                        || "список пуст")}</span>`);
            }
            if (r && r.error) Toast.error(r.error);
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = "Обновить список стран"; }
        }
    }

    async function _loadConfig() {
        // Форма — единственное место, где пользователь что-то печатает.
        // Перерисовываем только если её ещё нет: иначе затираем ввод.
        if (_configRendered && document.getElementById("opera-bind")) return;
        try {
            const cfg = await API.get("/api/opera-proxy/config");
            const el = document.getElementById("opera-config");
            if (!el) return;

            // Обновляем bind display
            const bindEl = document.getElementById("opera-bind-display");
            if (bindEl) bindEl.textContent = cfg.bind || "127.0.0.1:18080";

            el.innerHTML = `
                <div class="form-grid">
                    <div class="form-group">
                        <label>Страна</label>
                        <select id="opera-country" class="form-control">
                            <option value="EU" ${cfg.country === "EU" ? "selected" : ""}>EU (Европа)</option>
                            <option value="AS" ${cfg.country === "AS" ? "selected" : ""}>AS (Азия)</option>
                            <option value="AM" ${cfg.country === "AM" ? "selected" : ""}>AM (Америка)</option>
                            ${["EU", "AS", "AM"].includes(cfg.country) || !cfg.country ? ""
                              : `<option value="${esc(cfg.country)}" selected>${esc(cfg.country)}</option>`}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Bind address</label>
                        <input type="text" id="opera-bind" class="form-control"
                               value="${esc(cfg.bind || "127.0.0.1:18080")}">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="opera-socks" ${cfg.socks_mode ? "checked" : ""}>
                            SOCKS5 режим (иначе HTTP)
                        </label>
                    </div>
                    <div class="form-group">
                        <label>Proxy bypass (через запятую)</label>
                        <input type="text" id="opera-bypass" class="form-control"
                               value="${esc(cfg.proxy_bypass || "")}"
                               placeholder="api.example.com,*.local">
                    </div>
                    <div class="form-group">
                        <label>Fake SNI</label>
                        <input type="text" id="opera-sni" class="form-control"
                               value="${esc(cfg.fake_sni || "")}"
                               placeholder="www.google.com">
                    </div>
                    <div class="form-group">
                        <label>Verbosity</label>
                        <select id="opera-verbosity" class="form-control">
                            <option value="10" ${cfg.verbosity === 10 ? "selected" : ""}>Debug (10)</option>
                            <option value="20" ${cfg.verbosity === 20 ? "selected" : ""}>Info (20)</option>
                            <option value="30" ${cfg.verbosity === 30 ? "selected" : ""}>Warning (30)</option>
                            <option value="40" ${cfg.verbosity === 40 ? "selected" : ""}>Error (40)</option>
                            <option value="60" ${cfg.verbosity === 60 ? "selected" : ""}>Silent (60)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="opera-autostart" ${cfg.autostart ? "checked" : ""}>
                            Автозапуск и watchdog
                        </label>
                    </div>
                </div>
                <button class="btn btn-primary" id="opera-btn-save">Сохранить</button>
                <div class="form-hint" style="margin-top:8px;">
                    Настройки применяются при следующем запуске: после
                    «Сохранить» нажмите «Остановить» → «Запустить».
                    Галка включает и подъём после перезагрузки, и
                    перезапуск прокси при падении.
                </div>
            `;
            document.getElementById("opera-btn-save").addEventListener("click", _saveConfig);
            _configRendered = true;
        } catch (e) {
            const el = document.getElementById("opera-config");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    /** MR-111: Валидация port range */
    function _validatePort(val) {
        const p = parseInt(val, 10);
        if (isNaN(p) || p < 1 || p > 65535) return "Порт должен быть от 1 до 65535";
        return "";
    }

    /**
     * MR-111: Валидация bind address (host:port).
     * IPv6 — в скобках (`[::1]:18080`), как и требует бэкенд: раньше
     * такой адрес форма отвергала, хотя opera-proxy его принимает.
     */
    function _validateBind(val) {
        const s = (val || "").trim();
        if (!s) return "Bind address обязателен";
        let port;
        if (s.startsWith("[")) {
            const close = s.indexOf("]");
            if (close < 0 || s[close + 1] !== ":") return "Формат: [IPv6]:port";
            if (close === 1) return "Не указан хост";
            port = s.slice(close + 2);
        } else {
            const parts = s.split(":");
            if (parts.length !== 2) return "Формат: host:port (IPv6 — в скобках)";
            if (!parts[0]) return "Не указан хост";
            port = parts[1];
        }
        return _validatePort(port);
    }

    /** MR-111: Валидация домена / SNI */
    function _validateDomain(val) {
        if (!val) return "";
        if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) {
            return "Некорректный домен";
        }
        return "";
    }

    async function _saveConfig() {
        try {
            // MR-111: Client-side validation
            const bind = document.getElementById("opera-bind").value;
            const bindErr = _validateBind(bind);
            if (bindErr) {
                Toast.error("Bind: " + bindErr);
                return;
            }

            const country = document.getElementById("opera-country").value;
            const sni = document.getElementById("opera-sni").value;
            const sniErr = _validateDomain(sni);
            if (sniErr) {
                Toast.error("Fake SNI: " + sniErr);
                return;
            }

            await API.put("/api/opera-proxy/config", {
                country: country,
                bind: bind,
                socks_mode: document.getElementById("opera-socks").checked,
                proxy_bypass: document.getElementById("opera-bypass").value,
                fake_sni: sni,
                verbosity: parseInt(document.getElementById("opera-verbosity").value) || 20,
                autostart: document.getElementById("opera-autostart").checked,
            });
            const bindEl = document.getElementById("opera-bind-display");
            if (bindEl) bindEl.textContent = bind;
            Toast.success(_t("settings_saved"));
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _start() {
        try {
            const res = await API.post("/api/opera-proxy/up");
            if (res.ok) {
                Toast.success("Opera proxy запущен (" + (res.country || "?") + ")");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка запуска");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _stop() {
        try {
            const res = await API.post("/api/opera-proxy/down");
            if (res.ok) {
                Toast.success("Opera proxy остановлен");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка остановки");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    // ─── подключение как upstream в sing-box / mihomo ───
    //
    // Своим методом маршрутизации Opera Proxy быть не может: правило
    // единого слоя заворачивает трафик в ИНТЕРФЕЙС, а здесь только
    // локальный порт (подробнее — core/opera_proxy_chain.py).

    let _chainTargets = { singbox: [], mihomo: [] };

    async function _loadChainTargets() {
        try {
            const r = await API.get("/api/opera-proxy/chain/targets");
            _chainTargets = { singbox: (r && r.singbox) || [],
                              mihomo: (r && r.mihomo) || [] };
        } catch (_) {
            _chainTargets = { singbox: [], mihomo: [] };
        }
        _renderChainConfigs();
    }

    function _renderChainConfigs() {
        const engineSel = document.getElementById("opera-chain-engine");
        const cfgSel = document.getElementById("opera-chain-config");
        const btn = document.getElementById("opera-chain-btn");
        if (!engineSel || !cfgSel || !btn) return;
        const list = _chainTargets[engineSel.value] || [];
        if (!list.length) {
            cfgSel.innerHTML = '<option value="">Конфигов нет</option>';
            cfgSel.disabled = true;
            btn.disabled = true;
            return;
        }
        cfgSel.disabled = false;
        btn.disabled = false;
        cfgSel.innerHTML = list.map(c =>
            `<option value="${esc(c.name)}">${esc(c.name)}${
                c.running ? " (запущен)" : ""}</option>`).join("");
    }

    async function _chainAttach() {
        const engine = document.getElementById("opera-chain-engine").value;
        const config = document.getElementById("opera-chain-config").value;
        const box = document.getElementById("opera-chain-result");
        const btn = document.getElementById("opera-chain-btn");
        if (!config) return;
        btn.disabled = true;
        box.innerHTML = '<div class="form-hint">Добавляем…</div>';
        try {
            const r = await API.post("/api/opera-proxy/chain",
                                     { engine, config });
            if (!r || !r.ok) {
                box.innerHTML = `<div class="text-error">${
                    esc((r && r.error) || "Не удалось добавить")}</div>`;
                return;
            }
            const page = engine === "singbox" ? "#singbox" : "#mihomo";
            const what = engine === "singbox" ? "outbound" : "прокси";
            const warns = (r.warnings || []).map(w =>
                `<div class="form-hint text-error">${esc(w)}</div>`).join("");
            box.innerHTML = `
                <div class="form-hint">
                    ${r.replaced ? "Обновлён" : "Добавлен"} ${what}
                    <code>${esc(r.tag)}</code> в конфиг
                    <code>${esc(config)}</code>${
                        r.bypass_added
                            ? ", добавлено правило обхода <code>"
                              + esc("sec-tunnel.com") + "</code>"
                            : ""}.
                    Осталось направить на него нужные домены на странице
                    <a href="${page}">${engine === "singbox" ? "sing-box" : "mihomo"}</a>
                    и перезапустить движок.
                </div>${warns}`;
            Toast.success(`Opera Proxy добавлена в конфиг ${config}`);
        } catch (e) {
            box.innerHTML = `<div class="text-error">Ошибка: ${
                esc(e.message)}</div>`;
        } finally {
            btn.disabled = false;
        }
    }

    async function install() {
        Toast.info("Установка opera-proxy (последний релиз)...");
        try {
            // Ставится последний релиз апстрима, поэтому установка может
            // занять больше дефолтных 15с (обращение к GitHub + скачивание
            // ~8 МБ на медленном канале роутера).
            const res = await API.post("/api/opera-proxy/install", null,
                                       { timeout: 180000 });
            if (res.ok) {
                Toast.success(res.noop
                    ? "Уже актуальная версия: " + (res.version || "")
                    : "opera-proxy установлен: " + (res.version || ""));
                // Версия новее известной нам: апстрим не публикует файл
                // контрольных сумм, значит хэш сверить было не с чем.
                if (res.sha256_verified === false) {
                    Toast.info("Версия " + (res.tag || "") + " новее известной — "
                             + "sha256 не сверялся (скачано с GitHub по HTTPS)");
                }
                // Файл заменён, но работающий процесс остался на старой
                // версии — иначе непонятно, почему статус её и показывает.
                if (!res.noop) {
                    try {
                        const st = await API.get("/api/opera-proxy/status");
                        if (st && st.running) {
                            Toast.info("Перезапустите прокси, чтобы применить "
                                     + "новую версию");
                        }
                    } catch (_) { /* необязательно */ }
                }
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка установки");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    function _startPoll() {
        if (!_pollTimer) {
            _pollTimer = setInterval(_tick, POLL_MS);
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

    return { render, destroy, install };
})();
