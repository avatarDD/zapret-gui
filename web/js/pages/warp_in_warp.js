/**
 * warp_in_warp.js — WARP-in-WARP (MASQUE-based).
 *
 * Двойной туннель: MASQUE+MASQUE или MASQUE+AWG.
 * Внешний туннель маскирует внутренний от DPI.
 */

const WarpInWarpPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 3000;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>WARP-in-WARP (MASQUE)</h1>
                <span class="page-subtitle">Двойной туннель для максимального обхода DPI</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="wiw-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Компоненты</div>
                    <div class="card-body" id="wiw-detect">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Настройка</div>
                    <div class="card-body" id="wiw-config">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Действия</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="wiw-btn-up">Поднять</button>
                        <button class="btn btn-danger" id="wiw-btn-down">Опустить</button>
                        <button class="btn" id="wiw-btn-refresh">Обновить</button>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Схема</div>
                    <div class="card-body" id="wiw-scheme">
                        <div style="font-family:monospace; font-size:13px; line-height:1.8;">
                            <div>Клиент (LAN)</div>
                            <div>  ↓</div>
                            <div id="wiw-inner-label" style="color:var(--accent);">inner: ?</div>
                            <div>  ↓</div>
                            <div id="wiw-outer-label" style="color:var(--accent);">outer: ?</div>
                            <div>  ↓</div>
                            <div>Интернет</div>
                        </div>
                        <div class="text-muted" style="font-size:11px; margin-top:8px;">
                            <strong>MASQUE+MASQUE:</strong> оба TCP:443 (разные регионы/SNI)<br>
                            <strong>MASQUE+AWG:</strong> внешний TCP:443, внутренний UDP<br>
                            <strong>AWG+MASQUE:</strong> внешний UDP, внутренний TCP:443
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.getElementById("wiw-btn-up").onclick = _start;
        document.getElementById("wiw-btn-down").onclick = _stop;
        document.getElementById("wiw-btn-refresh").onclick = _refresh;

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
            const st = await API.get("/api/warp-in-warp/status");
            const el = document.getElementById("wiw-status");
            if (!el) return;
            const cls = st.active ? "status-ok" : "status-off";
            const text = st.active ? "Активен" : "Неактивен";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                    ${st.mode ? `<span class="text-muted">(${esc(st.mode)})</span>` : ""}
                </div>
                ${st.outer_iface ? `<div class="detail-row">Outer: <code>${esc(st.outer_iface)}</code></div>` : ""}
                ${st.inner_iface ? `<div class="detail-row">Inner: <code>${esc(st.inner_iface)}</code></div>` : ""}
            `;
            // Обновляем схему
            const innerLabel = document.getElementById("wiw-inner-label");
            const outerLabel = document.getElementById("wiw-outer-label");
            if (innerLabel) innerLabel.textContent = "inner: " + (st.inner_iface || "?");
            if (outerLabel) outerLabel.textContent = "outer: " + (st.outer_iface || "?");
        } catch (e) {
            const el = document.getElementById("wiw-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadDetect() {
        try {
            const d = await API.get("/api/warp-in-warp/detect");
            const el = document.getElementById("wiw-detect");
            if (!el) return;
            const usqueCls = d.usque_installed ? "status-ok" : "status-off";
            const awgCls = d.awg_available ? "status-ok" : "status-off";
            el.innerHTML = `
                <div class="detail-row">
                    <span class="status-dot ${usqueCls}"></span>
                    usque (MASQUE): ${d.usque_installed ? "Установлен" : "Не установлен"}
                </div>
                <div class="detail-row">
                    <span class="status-dot ${awgCls}"></span>
                    AmneziaWG: ${d.awg_available ? "Доступен" : "Не найден"}
                </div>
                <div class="detail-row">Архитектура: <code>${esc(d.arch || "?")}</code></div>
            `;
        } catch (e) {
            const el = document.getElementById("wiw-detect");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadConfig() {
        try {
            const st = await API.get("/api/warp-in-warp/status");
            const detect = await API.get("/api/warp-in-warp/detect");
            const el = document.getElementById("wiw-config");
            if (!el) return;

            if (st.active) {
                el.innerHTML = `
                    <div class="status-row" style="margin-bottom:12px;">
                        <span class="status-dot status-ok"></span>
                        <span>WARP-in-WARP активен (${esc(st.mode)})</span>
                    </div>
                `;
                return;
            }

            const canMasqueMasque = detect.usque_installed;
            const canMasqueAwg = detect.usque_installed && detect.awg_available;

            if (!canMasqueMasque && !canMasqueAwg) {
                el.innerHTML = `
                    <div style="padding:12px; background:rgba(211,158,0,0.1); border-left:3px solid #d39e00; border-radius:6px; font-size:13px;">
                        Для WARP-in-WARP нужен usque (MASQUE). Установите его на странице WARP/MASQUE.
                    </div>
                `;
                return;
            }

            el.innerHTML = `
                <div class="form-grid">
                    <div class="form-group">
                        <label>Режим</label>
                        <select id="wiw-mode" class="form-control" onchange="WarpInWarpPage.onModeChange()">
                            <option value="masque_masque" ${canMasqueMasque ? "" : "disabled"}>
                                MASQUE + MASQUE (двойной usque)
                            </option>
                            <option value="masque_awg" ${canMasqueAwg ? "" : "disabled"}>
                                MASQUE + AWG (usque → AmneziaWG)
                            </option>
                            <option value="awg_masque" ${canMasqueAwg ? "" : "disabled"}>
                                AWG + MASQUE (AmneziaWG → usque)
                            </option>
                        </select>
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            MASQUE+MASQUE: оба TCP:443 (разные регионы/SNI).<br>
                            MASQUE+AWG: внешний TCP:443, внутренний UDP (AmneziaWG).<br>
                            AWG+MASQUE: внешний UDP (AmneziaWG), внутренний TCP:443.<br>
                            <em>AWG+AWG доступен на странице AmneziaWG → WARP.</em>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Outer SNI (маскировка)</label>
                        <input type="text" id="wiw-outer-sni" class="form-control"
                               placeholder="ozon.ru" value="ozon.ru">
                    </div>
                    <div class="form-group" id="wiw-inner-sni-group">
                        <label>Inner SNI (MASQUE+MASQUE)</label>
                        <input type="text" id="wiw-inner-sni" class="form-control"
                               placeholder="www.google.com" value="www.google.com">
                    </div>
                    <div class="form-group">
                        <label>Outer конфиг (usque)</label>
                        <select id="wiw-outer-config" class="form-control">
                            <option value="">— загрузка...</option>
                        </select>
                    </div>
                    <div class="form-group" id="wiw-inner-config-group">
                        <label>Inner конфиг (usque/AWG)</label>
                        <select id="wiw-inner-config" class="form-control">
                            <option value="">— загрузка...</option>
                        </select>
                    </div>
                </div>
            `;

            // Загружаем списки конфигов
            await _loadConfigLists();
            onModeChange();
        } catch (e) {
            const el = document.getElementById("wiw-config");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadConfigLists() {
        try {
            // Usque configs
            const usqueData = await API.get("/api/usque/configs");
            const usqueConfigs = (usqueData.configs || []).map(c =>
                `<option value="${esc(c.path)}">${esc(c.name)}</option>`
            ).join("");

            const outerSel = document.getElementById("wiw-outer-config");
            const innerSel = document.getElementById("wiw-inner-config");
            if (outerSel) outerSel.innerHTML = `<option value="">— выберите outer —</option>${usqueConfigs}`;
            if (innerSel) innerSel.innerHTML = `<option value="">— выберите inner —</option>${usqueConfigs}`;

            // Если режим masque_awg — показываем AWG конфиги для inner
            // Пока оставляем usque конфиги, AWG добавим позже
        } catch (e) {
            // Тихо
        }
    }

    function onModeChange() {
        const mode = document.getElementById("wiw-mode")?.value;
        const innerSniGroup = document.getElementById("wiw-inner-sni-group");
        const outerSniGroup = document.getElementById("wiw-outer-sni")?.parentElement;
        // Inner SNI показываем только для masque_masque и awg_masque
        if (innerSniGroup) {
            innerSniGroup.style.display = (mode === "masque_masque" || mode === "awg_masque") ? "" : "none";
        }
        // Outer SNI показываем только для masque_masque и masque_awg
        if (outerSniGroup) {
            outerSniGroup.style.display = (mode === "masque_masque" || mode === "masque_awg") ? "" : "none";
        }
    }

    async function _start() {
        const mode = document.getElementById("wiw-mode")?.value || "masque_masque";
        const outerSni = document.getElementById("wiw-outer-sni")?.value || "";
        const innerSni = document.getElementById("wiw-inner-sni")?.value || "";
        const outerConfig = document.getElementById("wiw-outer-config")?.value || "";
        const innerConfig = document.getElementById("wiw-inner-config")?.value || "";

        if (!outerConfig) {
            Toast.error("Выберите outer конфиг");
            return;
        }
        if ((mode === "masque_masque" || mode === "awg_masque") && !innerConfig) {
            Toast.error("Выберите inner конфиг");
            return;
        }

        Toast.info("Запуск WARP-in-WARP...");
        try {
            const res = await API.post("/api/warp-in-warp/up", {
                mode, outer_sni: outerSni, inner_sni: innerSni,
                outer_config: outerConfig, inner_config: innerConfig,
                awg_conf: mode === "awg_masque" ? outerConfig : "",
            });
            if (res.ok) {
                Toast.success("WARP-in-WARP запущен (" + res.mode + ")");
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
            const res = await API.post("/api/warp-in-warp/down");
            if (res.ok) {
                Toast.success("WARP-in-WARP остановлен");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка остановки");
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

    return { render, destroy, onModeChange };
})();
