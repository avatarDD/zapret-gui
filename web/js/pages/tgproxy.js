/**
 * tgproxy.js — Страница управления Telegram MTProto Proxy.
 *
 * Два движка: teleproxy (ARM64,最强 DPI resistance) и
 * tg-mtproxy-client (MIPS, все архитектуры).
 */

const TgProxyPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Telegram Tunnel</h1>
                <span class="page-subtitle">MTProto Proxy — teleproxy / tg-mtproxy-client</span>
            </div>

            <div class="card-grid" id="tgproxy-status-card">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="tgproxy-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid" id="tgproxy-detect-card">
                <div class="card">
                    <div class="card-title">Доступные движки</div>
                    <div class="card-body" id="tgproxy-detect">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Настройки</div>
                    <div class="card-body" id="tgproxy-config">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Действия</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="tgproxy-btn-up">Запустить</button>
                        <button class="btn btn-danger" id="tgproxy-btn-down">Остановить</button>
                        <button class="btn" id="tgproxy-btn-refresh">Обновить</button>
                    </div>
                </div>
            </div>
        `;

        document.getElementById("tgproxy-btn-up").onclick = _start;
        document.getElementById("tgproxy-btn-down").onclick = _stop;
        document.getElementById("tgproxy-btn-refresh").onclick = _refresh;

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
            const st = await API.get("/api/tgproxy/status");
            const el = document.getElementById("tgproxy-status");
            if (!el) return;
            const cls = st.running ? "status-ok" : "status-off";
            const text = st.running ? "Работает" : "Остановлен";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                    ${st.engine ? `<span class="text-muted">(${esc(st.engine)})</span>` : ""}
                    ${st.pid ? `<span class="text-muted">PID ${st.pid}</span>` : ""}
                </div>
            `;
        } catch (e) {
            const el = document.getElementById("tgproxy-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadDetect() {
        try {
            const d = await API.get("/api/tgproxy/detect");
            const el = document.getElementById("tgproxy-detect");
            if (!el) return;
            const engines = d.engines || {};
            let html = `<div class="detail-row">Архитектура: <code>${esc(d.arch || "?")}</code></div>`;
            html += `<div class="detail-row">Выбран: <strong>${esc(d.selected || "нет")}</strong></div>`;
            html += '<table class="table"><thead><tr><th>Движок</th><th>Статус</th><th>Версия</th><th></th></tr></thead><tbody>';
            for (const [name, info] of Object.entries(engines)) {
                const cls = info.installed ? "status-ok" : "status-off";
                const text = info.installed ? "Установлен" : "Не найден";
                const actionBtn = info.installed
                    ? `<button class="btn btn-sm" onclick="TgProxyPage.selectEngine('${esc(name)}')">Выбрать</button>`
                    : `<button class="btn btn-primary btn-sm" onclick="TgProxyPage.installEngine('${esc(name)}')">Установить</button>`;
                html += `<tr>
                    <td>${esc(name)}</td>
                    <td><span class="status-dot ${cls}"></span> ${text}</td>
                    <td>${esc(info.version || "-")}</td>
                    <td>${actionBtn}</td>
                </tr>`;
            }
            html += '</tbody></table>';

            // Описание режимов
            html += '<div class="detail-row text-muted" style="margin-top:12px">';
            html += '<strong>teleproxy</strong> — Direct-to-DC на роутере. nfqws2 обходит DPI. Без VPS. <em>Только ARM64.</em><br>';
            html += '<strong>tg-mtproxy-client</strong> — Go-клиент. Все архитектуры (MIPS включительно).';
            html += ' Relay: z2k community (по умолчанию), свой VPS, или Cloudflare Worker.';
            html += '</div>';

            el.innerHTML = html;
        } catch (e) {
            const el = document.getElementById("tgproxy-detect");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadConfig() {
        try {
            const cfg = await API.get("/api/tgproxy/config");
            const el = document.getElementById("tgproxy-config");
            if (!el) return;
            el.innerHTML = `
                <div class="form-grid">
                    <div class="form-group">
                        <label>Режим</label>
                        <select id="tgproxy-engine" class="form-control">
                            <option value="auto" ${cfg.engine === "auto" ? "selected" : ""}>Авто (по архитектуре)</option>
                            <option value="teleproxy" ${cfg.engine === "teleproxy" ? "selected" : ""}>teleproxy — Direct-to-DC (без VPS)</option>
                            <option value="mtproto" ${cfg.engine === "mtproto" ? "selected" : ""}>tg-mtproxy-client (нужен relay)</option>
                        </select>
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            teleproxy: работает на роутере, подключается напрямую к Telegram DC.
                            nfqws2 обходит DPI. Без VPS.<br>
                            tg-mtproxy-client: нужен relay сервер (VPS / Cloudflare Worker / локальный).
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Порт</label>
                        <input type="number" id="tgproxy-port" class="form-control" value="${cfg.port || 9443}">
                    </div>
                    <div class="form-group">
                        <label>Teleproxy secret</label>
                        <input type="text" id="tgproxy-secret" class="form-control" value="${esc(cfg.teleproxy_secret || "")}" placeholder="hex secret">
                    </div>
                    <div class="form-group">
                        <label>Teleproxy domain (fake-TLS)</label>
                        <input type="text" id="tgproxy-domain" class="form-control" value="${esc(cfg.teleproxy_domain || "")}" placeholder="www.google.com">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="tgproxy-direct" ${cfg.teleproxy_direct_dc ? "checked" : ""}>
                            Direct-to-DC mode (teleproxy)
                        </label>
                    </div>
                    <div class="form-group">
                        <label>Tunnel URL (mtproto)</label>
                        <input type="text" id="tgproxy-tunnel-url" class="form-control"
                               value="${esc(cfg.tunnel_url || "")}"
                               placeholder="wss://213.176.74.63.nip.io/ws">
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            По умолчанию: z2k community relay (бесплатный). Можно заменить на свой VPS или Cloudflare Worker.
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Tunnel secret (mtproto)</label>
                        <input type="text" id="tgproxy-tunnel-secret" class="form-control" value="${esc(cfg.tunnel_secret || "")}">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="tgproxy-autostart" ${cfg.autostart ? "checked" : ""}>
                            Автозапуск
                        </label>
                    </div>
                </div>
                <button class="btn btn-primary" id="tgproxy-btn-save">Сохранить</button>
            `;
            document.getElementById("tgproxy-btn-save").onclick = _saveConfig;
        } catch (e) {
            const el = document.getElementById("tgproxy-config");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _saveConfig() {
        try {
            await API.put("/api/tgproxy/config", {
                engine: document.getElementById("tgproxy-engine").value,
                port: parseInt(document.getElementById("tgproxy-port").value) || 9443,
                teleproxy_secret: document.getElementById("tgproxy-secret").value,
                teleproxy_domain: document.getElementById("tgproxy-domain").value,
                teleproxy_direct_dc: document.getElementById("tgproxy-direct").checked,
                tunnel_url: document.getElementById("tgproxy-tunnel-url").value,
                tunnel_secret: document.getElementById("tgproxy-tunnel-secret").value,
                autostart: document.getElementById("tgproxy-autostart").checked,
            });
            Toast.success("Настройки сохранены");
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _start() {
        try {
            const res = await API.post("/api/tgproxy/up");
            if (res.ok) {
                Toast.success("Telegram proxy запущен (" + (res.engine || "?") + ")");
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
            const res = await API.post("/api/tgproxy/down");
            if (res.ok) {
                Toast.success("Telegram proxy остановлен");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка остановки");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function selectEngine(name) {
        try {
            await API.post("/api/tgproxy/engine", { engine: name });
            Toast.success("Движок: " + name);
            await _refresh();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function installEngine(name) {
        Toast.info("Установка " + name + "...");
        try {
            const res = await API.post("/api/tgproxy/install/" + name);
            if (res.ok) {
                Toast.success(name + " установлен: " + (res.version || ""));
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

    return { render, destroy, selectEngine, installEngine };
})();
