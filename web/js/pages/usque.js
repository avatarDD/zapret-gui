/**
 * usque.js — Страница управления WARP/MASQUE (usque).
 *
 * Показывает статус туннеля, список конфигов, управление запуском.
 */

const UsquePage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>WARP / MASQUE</h1>
                <span class="page-subtitle">Cloudflare WARP через usque-keenetic</span>
            </div>

            <div class="card-grid" id="usque-env-card">
                <div class="card">
                    <div class="card-title">Окружение</div>
                    <div class="card-body" id="usque-env">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid" id="usque-configs-card">
                <div class="card">
                    <div class="card-title">Конфиги</div>
                    <div class="card-body" id="usque-configs">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Действия</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="usque-btn-register">Зарегистрировать WARP</button>
                        <button class="btn" id="usque-btn-refresh">Обновить</button>
                    </div>
                </div>
            </div>
        `;

        document.getElementById("usque-btn-register").onclick = _register;
        document.getElementById("usque-btn-refresh").onclick = _refresh;

        await _refresh();
        _startPoll();
    }

    function destroy() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    }

    async function _refresh() {
        await Promise.all([_loadEnv(), _loadConfigs()]);
    }

    async function _loadEnv() {
        try {
            const env = await API.get("/api/usque/environment");
            const el = document.getElementById("usque-env");
            if (!el) return;
            if (env.installed) {
                el.innerHTML = `
                    <div class="status-row">
                        <span class="status-dot status-ok"></span>
                        <span>Установлен: <strong>${esc(env.version || "?")}</strong></span>
                    </div>
                    <div class="detail-row">Бинарник: <code>${esc(env.binary)}</code></div>
                    <div class="detail-row">Архитектура: <code>${esc(env.arch)}</code></div>
                `;
            } else {
                el.innerHTML = `
                    <div class="status-row">
                        <span class="status-dot status-error"></span>
                        <span>Не установлен</span>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="UsquePage.install()" style="margin-top:8px;">
                        Установить usque
                    </button>
                `;
            }
        } catch (e) {
            const el = document.getElementById("usque-env");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadConfigs() {
        try {
            const data = await API.get("/api/usque/configs");
            const el = document.getElementById("usque-configs");
            if (!el) return;
            const configs = data.configs || [];
            if (!configs.length) {
                el.innerHTML = `<p class="text-muted">Нет конфигов. Нажмите "Зарегистрировать WARP" для создания.</p>`;
                return;
            }
            let html = '<table class="table"><thead><tr>';
            html += '<th>Имя</th><th>Интерфейс</th><th>Статус</th><th>Действия</th>';
            html += '</tr></thead><tbody>';
            for (const c of configs) {
                const statusCls = c.active ? "status-ok" : "status-off";
                const statusText = c.active ? "Работает" : "Остановлен";
                const toggleBtn = c.active
                    ? `<button class="btn btn-danger btn-sm" onclick="UsquePage.stop('${esc(c.name)}')">Стоп</button>`
                    : `<button class="btn btn-primary btn-sm" onclick="UsquePage.start('${esc(c.name)}')">Старт</button>`;
                html += `<tr>
                    <td>${esc(c.name)}</td>
                    <td><code>${esc(c.iface)}</code></td>
                    <td><span class="status-dot ${statusCls}"></span> ${statusText}</td>
                    <td>${toggleBtn}
                        <button class="btn btn-sm" onclick="UsquePage.remove('${esc(c.name)}')">Удалить</button>
                    </td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;
        } catch (e) {
            const el = document.getElementById("usque-configs");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _register() {
        const name = prompt("Имя конфига:", "warp-default");
        if (!name) return;
        try {
            const res = await API.post("/api/usque/register", { name });
            if (res.ok) {
                Toast.success("WARP-сессия зарегистрирована");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка регистрации");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
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
        if (!confirm(`Удалить конфиг "${name}"?`)) return;
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
            const res = await API.post("/api/usque/install");
            if (res.ok) {
                Toast.success("usque установлен: " + (res.version || ""));
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

    return { render, destroy, start, stop, remove, install };
})();
