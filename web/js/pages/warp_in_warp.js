/**
 * warp_in_warp.js — WARP-in-WARP (MASQUE-based).
 *
 * Двойной туннель: MASQUE+MASQUE или MASQUE+AWG.
 * Внешний туннель маскирует внутренний от DPI.
 */

const WarpInWarpPage = (() => {
    let _pollTimer = null;
    let _visibilityHandler = null;
    let _inFlight = false;
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
                            <strong>MASQUE+MASQUE:</strong> оба WARP-слоя (H3/QUIC по умолчанию)<br>
                            <strong>MASQUE+AWG:</strong> внешний MASQUE, внутренний UDP<br>
                            <strong>AWG+MASQUE:</strong> внешний UDP, внутренний MASQUE
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.getElementById("wiw-btn-up").addEventListener("click", _start);
        document.getElementById("wiw-btn-down").addEventListener("click", _stop);
        document.getElementById("wiw-btn-refresh").addEventListener("click", _refresh);

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

    function _startPoll() {
        if (_pollTimer) return;
        _pollTimer = setInterval(_refresh, POLL_MS);
    }

    function _stopPoll() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    }

    async function _refresh() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            // MR-110: загружаем status и detect один раз, передаём в все функции
            const [st, detect] = await Promise.all([
                API.get("/api/warp-in-warp/status"),
                API.get("/api/warp-in-warp/detect"),
            ]);
            await Promise.all([
                _loadStatus(st),
                _loadDetect(detect),
                _loadConfig(st, detect),
            ]);
        } finally {
            _inFlight = false;
        }
    }

    async function _loadStatus(st) {
        try {
            if (!st) st = await API.get("/api/warp-in-warp/status");
            const el = document.getElementById("wiw-status");
            if (!el) return;
            const cls = st.active ? "status-ok" : "status-off";
            const text = st.active ? _t("status_active") : _t("status_inactive");
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

    async function _loadDetect(d) {
        try {
            if (!d) d = await API.get("/api/warp-in-warp/detect");
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

    async function _loadConfig(st, detect) {
        try {
            // MR-110: принимаем результаты из _refresh(), если не переданы — запрашиваем
            if (!st) st = await API.get("/api/warp-in-warp/status");
            if (!detect) detect = await API.get("/api/warp-in-warp/detect");
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
                        <select id="wiw-mode" class="form-control">
                            <option value="masque_masque" ${canMasqueMasque ? "" : "disabled"}
                                title="Двойной MASQUE. По умолчанию usque использует H3/QUIC; H2/TCP можно включить в профиле usque.">
                                MASQUE + MASQUE (двойной usque)
                            </option>
                            <option value="masque_awg" ${canMasqueAwg ? "" : "disabled"}
                                title="Внешний MASQUE маскирует трафик, внутренний AmneziaWG обеспечивает шифрование WireGuard.">
                                MASQUE + AWG (usque → AmneziaWG)
                            </option>
                            <option value="awg_masque" ${canMasqueAwg ? "" : "disabled"}
                                title="Внешний AmneziaWG (UDP) + внутренний MASQUE. Используйте только если это действительно нужно: второй слой повышает latency.">
                                AWG + MASQUE (AmneziaWG → usque)
                            </option>
                            <option value="awg_awg" disabled
                                title="AmneziaWG + AmneziaWG — двойной WG-туннель. Доступен на странице AmneziaWG → WARP.">
                                AWG + AWG (двойной AmneziaWG)
                            </option>
                        </select>
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            <span class="mode-hint" data-mode="masque_masque" style="display:none;">
                                ✅ <strong>MASQUE+MASQUE:</strong> по умолчанию H3/QUIC; режим H2/TCP:443
                                задаётся в конфиге usque. Второй слой не гарантирует невидимость для DPI.
                            </span>
                            <span class="mode-hint" data-mode="masque_awg" style="display:none;">
                                🔒 <strong>MASQUE+AWG:</strong> Внешний MASQUE + внутренний
                                AmneziaWG (UDP). Даёт сочетание маскировки трафика и WG-шифрования.
                            </span>
                            <span class="mode-hint" data-mode="awg_masque" style="display:none;">
                                🔄 <strong>AWG+MASQUE:</strong> Внешний AmneziaWG (UDP) + внутренний
                                MASQUE. Альтернатива при проблемах с внешним MASQUE.
                            </span>
                            <span class="mode-hint" data-mode="awg_awg" style="display:none;">
                                ℹ️ <strong>AWG+AWG:</strong> Двойной AmneziaWG. Доступен на странице
                                <a href="#awg-warp">AmneziaWG → WARP</a>.
                            </span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Транспорт usque</label>
                        <select id="wiw-transport-profile" class="form-control">
                            <option value="performance" selected>Performance — H3/QUIC</option>
                            <option value="restricted">Restricted network — H2/TCP:443</option>
                            <option value="auto">Auto — H3, затем H2 при подтверждённом сбое</option>
                        </select>
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            H2 внутри H2 запрещён. MASQUE + MASQUE остаётся экспериментальным:
                            двойной слой увеличивает задержку и не делает внешний трафик
                            невидимым для DPI.
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Outer SNI (маскировка)</label>
                        <!-- MR-109: убран хардкод ozon.ru -->
                        <input type="text" id="wiw-outer-sni" class="form-control"
                               placeholder="например: zt-masque.cloudflareclient.com" value="">
                    </div>
                    <div class="form-group" id="wiw-inner-sni-group">
                        <label>Inner SNI (MASQUE+MASQUE)</label>
                        <!-- MR-109: убран хардкод www.google.com -->
                        <input type="text" id="wiw-inner-sni" class="form-control"
                               placeholder="например: www.google.com" value="">
                    </div>
                    <div class="form-group" id="wiw-outer-config-group">
                        <label>Outer конфиг (usque)</label>
                        <select id="wiw-outer-config" class="form-control">
                            <option value="">— загрузка...</option>
                        </select>
                    </div>
                    <div class="form-group" id="wiw-inner-config-group">
                        <label>Inner конфиг (usque)</label>
                        <select id="wiw-inner-config" class="form-control">
                            <option value="">— загрузка...</option>
                        </select>
                    </div>
                    <div class="form-group" id="wiw-awg-config-group" style="display:none;">
                        <label>AWG конфиг</label>
                        <select id="wiw-awg-config" class="form-control">
                            <option value="">— загрузка...</option>
                        </select>
                    </div>
                    <div class="form-group" id="wiw-endpoint-group">
                        <label>Endpoint inner-сессии (для маршрутизации)</label>
                        <input type="text" id="wiw-inner-endpoint" class="form-control"
                               placeholder="IP или hostname MASQUE endpoint">
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            Нужен, когда inner-туннель — MASQUE, чтобы его handshake гарантированно прошёл через outer.
                        </div>
                    </div>
                </div>
            `;

            // MR-69 (partial): привязываем события через addEventListener, а не inline onchange
            const modeSelect = document.getElementById("wiw-mode");
            if (modeSelect) modeSelect.addEventListener("change", onModeChange);

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
            // Usque and AWG configs are different namespaces. Do not pass a
            // usque path as an AWG config name.
            const [usqueData, awgData] = await Promise.all([
                API.get("/api/usque/configs"),
                API.get("/api/awg/configs").catch(() => ({ configs: [] })),
            ]);
            const usqueConfigs = (usqueData.configs || []).map(c =>
                `<option value="${esc(c.path)}">${esc(c.name)}</option>`
            ).join("");
            const awgConfigs = (awgData.configs || []).map(c =>
                `<option value="${esc(c.name)}">${esc(c.name)}</option>`
            ).join("");

            const outerSel = document.getElementById("wiw-outer-config");
            const innerSel = document.getElementById("wiw-inner-config");
            if (outerSel) outerSel.innerHTML = `<option value="">— выберите outer —</option>${usqueConfigs}`;
            if (innerSel) innerSel.innerHTML = `<option value="">— выберите inner —</option>${usqueConfigs}`;
            const awgSel = document.getElementById("wiw-awg-config");
            if (awgSel) awgSel.innerHTML = `<option value="">— выберите AWG —</option>${awgConfigs}`;
        } catch (e) {
            // Тихо
        }
    }

    function onModeChange() {
        const mode = document.getElementById("wiw-mode")?.value;
        const innerSniGroup = document.getElementById("wiw-inner-sni-group");
        const outerSniGroup = document.getElementById("wiw-outer-sni")?.parentElement;
        const innerConfigGroup = document.getElementById("wiw-inner-config-group");
        const awgConfigGroup = document.getElementById("wiw-awg-config-group");
        const outerConfigGroup = document.getElementById("wiw-outer-config-group");
        const endpointGroup = document.getElementById("wiw-endpoint-group");
        // Inner SNI показываем только для masque_masque и awg_masque
        if (innerSniGroup) {
            innerSniGroup.style.display = (mode === "masque_masque" || mode === "awg_masque") ? "" : "none";
        }
        // Outer SNI показываем только для masque_masque и masque_awg
        if (outerSniGroup) {
            outerSniGroup.style.display = (mode === "masque_masque" || mode === "masque_awg") ? "" : "none";
        }
        if (innerConfigGroup) {
            innerConfigGroup.style.display = (mode === "masque_masque" || mode === "awg_masque") ? "" : "none";
        }
        if (outerConfigGroup) outerConfigGroup.style.display = mode === "awg_masque" ? "none" : "";
        if (awgConfigGroup) {
            awgConfigGroup.style.display = (mode === "masque_awg" || mode === "awg_masque") ? "" : "none";
        }
        if (endpointGroup) endpointGroup.style.display = (mode === "masque_masque" || mode === "awg_masque") ? "" : "none";
        // MR-130: показываем подсказку для выбранного режима
        document.querySelectorAll(".mode-hint").forEach(el => {
            el.style.display = el.dataset.mode === mode ? "" : "none";
        });
    }

    async function _start() {
        const mode = document.getElementById("wiw-mode")?.value || "masque_masque";
        const outerSni = document.getElementById("wiw-outer-sni")?.value || "";
        const innerSni = document.getElementById("wiw-inner-sni")?.value || "";
        const outerConfig = document.getElementById("wiw-outer-config")?.value || "";
        const innerConfig = document.getElementById("wiw-inner-config")?.value || "";
        const awgConfig = document.getElementById("wiw-awg-config")?.value || "";
        const innerEndpointHost = document.getElementById("wiw-inner-endpoint")?.value.trim() || "";
        const transportProfile = document.getElementById("wiw-transport-profile")?.value || "performance";

        if (mode !== "awg_masque" && !outerConfig) {
            Toast.error("Выберите outer конфиг");
            return;
        }
        if ((mode === "masque_masque" || mode === "awg_masque") && !innerConfig) {
            Toast.error("Выберите inner конфиг");
            return;
        }
        if ((mode === "masque_awg" || mode === "awg_masque") && !awgConfig) {
            Toast.error("Выберите AWG конфиг");
            return;
        }
        if ((mode === "masque_masque" || mode === "awg_masque") && !innerEndpointHost) {
            Toast.error("Укажите endpoint inner-сессии для безопасной маршрутизации");
            return;
        }

        Toast.info("Запуск WARP-in-WARP...");
        try {
            const res = await API.post("/api/warp-in-warp/up", {
                mode, outer_sni: outerSni, inner_sni: innerSni,
                outer_config: outerConfig, inner_config: innerConfig,
                awg_conf: awgConfig,
                inner_endpoint_host: innerEndpointHost,
                transport_profile: transportProfile,
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



    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, onModeChange };
})();
