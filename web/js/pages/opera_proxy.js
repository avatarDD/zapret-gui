/**
 * opera_proxy.js — Страница управления Opera Proxy.
 *
 * Standalone Opera VPN: HTTP/SOCKS5 прокси через SurfEasy.
 * Zero-config: запустил → прокси работает.
 */

const OperaProxyPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Opera Proxy</h1>
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

        document.getElementById("opera-btn-up").onclick = _start;
        document.getElementById("opera-btn-down").onclick = _stop;
        document.getElementById("opera-btn-refresh").onclick = _refresh;

        await _refresh();
        _startPoll();
    }

    function destroy() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    }

    async function _refresh() {
        await Promise.all([_loadStatus(), _loadDetect(), _loadConfig()]);
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

    async function _loadDetect() {
        try {
            const d = await API.get("/api/opera-proxy/detect");
            const el = document.getElementById("opera-detect");
            if (!el) return;
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
                    <button class="btn btn-primary btn-sm" onclick="OperaProxyPage.install()" style="margin-top:8px;">
                        Установить opera-proxy
                    </button>
                `;
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
            document.getElementById("opera-btn-save").onclick = _saveConfig;
        } catch (e) {
            const el = document.getElementById("opera-config");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _saveConfig() {
        try {
            await API.put("/api/opera-proxy/config", {
                country: document.getElementById("opera-country").value,
                bind: document.getElementById("opera-bind").value,
                socks_mode: document.getElementById("opera-socks").checked,
                proxy_bypass: document.getElementById("opera-bypass").value,
                fake_sni: document.getElementById("opera-sni").value,
                verbosity: parseInt(document.getElementById("opera-verbosity").value) || 20,
                autostart: document.getElementById("opera-autostart").checked,
            });
            Toast.success("Настройки сохранены");
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
        _pollTimer = setInterval(_refresh, POLL_MS);
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, install };
})();
