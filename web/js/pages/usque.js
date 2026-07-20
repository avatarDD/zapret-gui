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

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>${_t('warp_masque')}</h1>
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

        // MR-69: addEventListener вместо onclick
        document.getElementById("usque-btn-register").addEventListener("click", _register);
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
        } finally {
            _inFlight = false;
        }
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
                    <button class="btn btn-primary btn-sm" id="usque-install-btn" style="margin-top:8px;">
                        Установить usque
                    </button>
                `;
                document.getElementById("usque-install-btn")?.addEventListener("click", install);
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
                    ? `<button class="btn btn-danger btn-sm action-stop" data-name="${esc(c.name)}">Стоп</button>`
                    : `<button class="btn btn-primary btn-sm action-start" data-name="${esc(c.name)}">Старт</button>`;
                html += `<tr>
                    <td>${esc(c.name)}</td>
                    <td><code>${esc(c.iface)}</code></td>
                    <td><span class="status-dot ${statusCls}"></span> ${statusText}</td>
                    <td>${toggleBtn}
                        <button class="btn btn-sm action-remove" data-name="${esc(c.name)}">Удалить</button>
                    </td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;

            // Навешиваем события безопасности через addEventListener
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
        } catch (e) {
            const el = document.getElementById("usque-configs");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
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
            <div style="margin-bottom:16px;">
                <input type="text" id="prompt-modal-input" class="form-input" 
                       value="${esc(defaultValue)}" placeholder="${esc(placeholder)}"
                       style="width:100%; box-sizing:border-box; padding:8px; border-radius:4px; border:1px solid var(--border, #2d313f); background:var(--bg-input, #0f111a); color:var(--text-main, #e1e4ea);" />
                <div id="prompt-modal-error" style="color:var(--text-error, #ff5370); font-size:0.85rem; margin-top:4px; display:none;"></div>
            </div>
            <div style="display:flex; justify-content:flex-end; gap:8px;">
                <button class="btn" id="prompt-modal-cancel">Отмена</button>
                <button class="btn btn-primary" id="prompt-modal-ok">ОК</button>
            </div>
        `;

        overlay.appendChild(content);
        document.body.appendChild(overlay);

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
            overlay.remove();
            callback(val);
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

    async function _register() {
        // MR-100: Используем наш кастомный prompt-modal вместо native prompt()
        _showPromptModal("Имя конфига:", "warp-default", "Имя новой сессии", async (name) => {
            try {
                const res = await API.post("/api/usque/register", { name });
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
