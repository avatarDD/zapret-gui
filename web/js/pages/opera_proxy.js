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
                            Для transparent proxy на роутере используйте redsocks/tproxy
                            с перенаправлением трафика на этот порт.
                        </p>
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
        document.getElementById("opera-btn-refresh").addEventListener("click", _refresh);

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
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            await Promise.all([_loadStatus(), _loadDetect(), _loadConfig()]);
        } finally {
            _inFlight = false;
        }
    }

    async function _loadStatus() {
        try {
            const st = await API.get("/api/opera-proxy/status");
            const el = document.getElementById("opera-status");
            if (!el) return;
            const cls = st.running ? "status-ok" : "status-off";
            const text = st.running ? "Работает" : "Остановлен";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                    ${st.pid ? `<span class="text-muted">PID ${st.pid}</span>` : ""}
                </div>
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
                const countries = d.countries || [];
                if (countries.length) {
                    html += '<div class="detail-row">Страны: ';
                    html += countries.map(c =>
                        `<span class="badge">${esc(c.code)}</span> ${esc(c.name)}`
                    ).join(', ');
                    html += '</div>';
                }
                el.innerHTML = html;
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

    async function _loadConfig() {
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
                            Автозапуск
                        </label>
                    </div>
                </div>
                <button class="btn btn-primary" id="opera-btn-save">Сохранить</button>
            `;
            document.getElementById("opera-btn-save").addEventListener("click", _saveConfig);
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

    /** MR-111: Валидация bind address (host:port) */
    function _validateBind(val) {
        if (!val) return "Bind address обязателен";
        const parts = val.split(":");
        if (parts.length !== 2) return "Формат: host:port";
        const portErr = _validatePort(parts[1]);
        if (portErr) return portErr;
        return "";
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

    async function install() {
        Toast.info("Установка opera-proxy...");
        try {
            const res = await API.post("/api/opera-proxy/install");
            if (res.ok) {
                Toast.success("opera-proxy установлен: " + (res.version || ""));
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

    return { render, destroy, install };
})();
