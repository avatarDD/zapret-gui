/**
 * tgproxy.js — Обход блокировки Telegram.
 *
 * Основной движок — tg-ws-proxy-go (tgwsproxy), резервный —
 * tg-mtproxy-client (mtproto). teleproxy убран — см. обсуждение в
 * аудите: его Direct-to-DC режим бесполезен при блокировке по
 * IP-диапазону датацентров Telegram, а не только при точечном DPI.
 *
 * Важно: значения из полей ввода (cf_domain и т.п.) НИКОГДА не
 * подставляются в inline onclick="...('${x}')" — только через
 * data-атрибуты + addEventListener. См. ISSUE-025 в аудите: esc()
 * защищает от разрыва HTML, но не от разрыва JS-строки внутри
 * HTML-атрибута — оба этих поля являются пользовательским вводом,
 * и их нельзя собирать в JS-код через шаблонные строки.
 */

const TgProxyPage = (() => {
    let _visibilityHandler = null;
    let _inFlight = false;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Telegram Tunnel${typeof Help !== 'undefined' ? Help.button('tgproxy') : ''}</h1>
                <span class="page-subtitle">tg-ws-proxy-go (основной) / tg-mtproxy-client (резерв)</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="tgproxy-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">tg-ws-proxy-go — настройки</div>
                    <div class="card-body" id="tgwsproxy-config">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">tg-ws-proxy-go — подключение</div>
                    <div class="card-body" id="tgwsproxy-connect">—</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">tg-mtproxy-client (резервный)</div>
                    <div class="card-body" id="mtproto-panel">Загрузка...</div>
                </div>
            </div>
        `;

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
            await Promise.all([_loadStatusDirect(), _loadTgwsproxyConfig(), _loadMtprotoPanel()]);
        } finally {
            _inFlight = false;
        }
    }

    // ─────────────────────────── статус ───────────────────────────

    async function _loadStatusDirect() {
        const el = document.getElementById("tgproxy-status");
        if (!el) return;
        try {
            const st = await API.get("/api/tgproxy/status");
            const rows = [
                _statusRow("tg-ws-proxy-go", st.tgwsproxy),
                _statusRow("tg-mtproxy-client", st.mtproto),
            ].join("");
            el.innerHTML = `<div class="status-list">${rows}</div>`;
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadStatus() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            await _loadStatusDirect();
        } finally {
            _inFlight = false;
        }
    }

    function _statusRow(label, st) {
        st = st || {};
        const running = !!st.running;
        const cls = running ? "status-ok" : "status-off";
        const text = running ? _t("status_running") : _t("status_stopped");
        return `<div class="status-row">
            <span class="status-dot ${cls}"></span>
            <span>${esc(label)}</span>
            <span class="text-muted">${text}</span>
            ${st.port ? `<span class="text-muted">порт ${esc(String(st.port))}</span>` : ""}
        </div>`;
    }

    // ─────────────────────────── tgwsproxy: конфиг ───────────────────────────

    async function _loadTgwsproxyConfig() {
        const el = document.getElementById("tgwsproxy-config");
        if (!el) return;
        try {
            const det = await API.get("/api/tgproxy/detect");
            if (!det.tgwsproxy || !det.tgwsproxy.installed) {
                el.innerHTML = `<div class="text-muted">
                    tg-ws-proxy-go не установлен на роутере (пакет opkg
                    <code>tg-ws-proxy</code>). Установите через Entware
                    package manager, затем обновите страницу.
                </div>`;
                return;
            }

            const [cfgRes, tunnelsRes] = await Promise.all([
                API.get("/api/tgproxy/tgwsproxy/config"),
                API.get("/api/tgproxy/tgwsproxy/tunnels"),
            ]);
            const cfg = (cfgRes && cfgRes.config) || {};
            const tunnels = (tunnelsRes && tunnelsRes.tunnels) || [];
            const configuredPoolSize = Number.isFinite(Number(cfg.pool_size)) ? Number(cfg.pool_size) : 2;

            // Режим выхода к Telegram DC определяем по текущему конфигу:
            // если задан cf_domain/cf_worker_domain — режим "cfdomain";
            // если нет и есть активный маршрут через туннель — "tunnel"
            // (сам факт наличия активного маршрута узнаём отдельным
            // полем route_via_tunnel, которое отдаёт бэкенд); иначе —
            // "direct". Режимы взаимоисключающие: если задан
            // CF-домен, исходящее соединение идёт на IP Cloudflare, а
            // не на IP датацентра Telegram — маршрут через WARP-туннель
            // (он матчит именно IP датацентра) в этом случае просто ни
            // на что не влияет, поэтому сочетать их бессмысленно.
            const hasCf = !!(cfg.cf_domain || cfg.cf_worker_domain);
            const allowedModes = ["direct", "cfcommunity", "cfdomain", "hybrid", "tunnel"];
            const currentMode = allowedModes.includes(cfg.mode)
                ? cfg.mode
                : (hasCf ? "cfdomain" : (cfg.route_via_tunnel ? "tunnel" : "direct"));

            const tunnelOptions = tunnels.length
                ? tunnels.map(t => `<option value="${esc(t.kind)}::${esc(t.iface)}"
                        ${(cfg.route_via_tunnel &&
                           cfg.route_via_tunnel.kind === t.kind &&
                           cfg.route_via_tunnel.iface === t.iface) ? "selected" : ""}
                        ${t.running ? "" : "disabled"}>
                        ${esc(t.label)} ${t.running ? "" : "(не запущен)"}
                    </option>`).join("")
                : `<option value="">Нет доступных туннелей</option>`;

            el.innerHTML = `
                <div class="form-grid">
                    <div class="form-group">
                        <label>Порт</label>
                        <input type="number" id="tgws-port" class="form-control"
                               value="${esc(String(cfg.port || 1443))}">
                    </div>

                    <div class="form-group">
                        <label>Fake-TLS домен (опционально)</label>
                        <input type="text" id="tgws-fake-tls" class="form-control"
                               value="${esc(cfg.fake_tls_domain || "")}"
                               placeholder="www.google.com">
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            Это fake-TLS только для входящего соединения Telegram-клиента
                            к локальному proxy (режим ee). Он не меняет TLS fingerprint
                            исходящего WSS-соединения роутера до Telegram/Cloudflare.
                        </div>
                    </div>

                    <div class="form-group">
                        <label>DC IP (прямое подключение, опционально)</label>
                        <input type="text" id="tgws-dc-ip" class="form-control"
                               value="${esc(cfg.dc_ip_default || "")}"
                               placeholder="149.154.167.220">
                    </div>
                </div>

                <div class="form-group" style="margin-top:16px;">
                    <label>Как выходить на датацентр Telegram</label>
                    <div class="radio-group">
                        <label class="radio-option">
                            <input type="radio" name="tgws-mode" value="direct"
                                   ${currentMode === "direct" ? "checked" : ""}>
                            Прямое подключение
                        </label>
                        <label class="radio-option">
                            <input type="radio" name="tgws-mode" value="cfcommunity"
                                   ${currentMode === "cfcommunity" ? "checked" : ""}>
                            Cloudflare community
                        </label>
                        <label class="radio-option">
                            <input type="radio" name="tgws-mode" value="cfdomain"
                                   ${currentMode === "cfdomain" ? "checked" : ""}>
                            Cloudflare custom domain / Worker
                        </label>
                        <label class="radio-option">
                            <input type="radio" name="tgws-mode" value="hybrid"
                                   ${currentMode === "hybrid" ? "checked" : ""}>
                            Hybrid: Direct, затем Cloudflare fallback
                        </label>
                        <label class="radio-option">
                            <input type="radio" name="tgws-mode" value="tunnel"
                                   ${currentMode === "tunnel" ? "checked" : ""}>
                            Через существующий WARP-туннель (AWG+WARP / MASQUE+WARP)
                        </label>
                    </div>
                </div>

                <div id="tgws-mode-cfcommunity" class="mode-panel"
                     style="display:${currentMode === "cfcommunity" ? "block" : "none"}">
                    <div class="alert alert-warning" style="font-size:12px;">
                        Используется публичный community pool. Для постоянной эксплуатации
                        предпочтительнее собственный CF-домен: общий pool может быть
                        перегружен или заблокирован.
                    </div>
                </div>

                <div id="tgws-mode-direct" class="mode-panel"
                     style="display:${currentMode === "direct" ? "block" : "none"}">
                    <div class="text-muted" style="font-size:12px;">
                        Соединение идёт напрямую на IP датацентра Telegram (поле
                        «DC IP» выше). Работает только если провайдер не блокирует
                        этот диапазон IP целиком.
                    </div>
                </div>

                <div id="tgws-mode-hybrid" class="mode-panel"
                     style="display:${currentMode === "hybrid" ? "block" : "none"}">
                    <div class="text-muted" style="font-size:12px;">
                        Сначала прямое соединение с Telegram DC, затем Cloudflare community
                        fallback. Передаётся <code>--cfproxy-priority=false</code>.
                    </div>
                </div>

                <div id="tgws-mode-cfdomain" class="mode-panel"
                     style="display:${currentMode === "cfdomain" ? "block" : "none"}">
                    <div class="form-grid">
                        <div class="form-group">
                            <label>Свой CF-домен (Cloudflare CDN, «оранжевое облако»)</label>
                            <input type="text" id="tgws-cf-domain" class="form-control"
                                   value="${esc(cfg.cf_domain || "")}"
                                   placeholder="proxy.мойдомен.ру">
                            <div class="text-muted" style="font-size:11px; margin-top:4px;">
                                Для custom-режима обязательно заполните это поле
                                либо Worker справа. Community pool вынесен в
                                отдельный режим. Требует домен, добавленный в
                                Cloudflare с включённым проксированием (см.
                                <a href="https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/CfProxy.md"
                                   target="_blank" rel="noopener">CfProxy.md</a>).
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Свой CF-Worker домен (альтернатива CF-домену)</label>
                            <input type="text" id="tgws-cf-worker" class="form-control"
                                   value="${esc(cfg.cf_worker_domain || "")}"
                                   placeholder="my-proxy.username.workers.dev">
                            <div class="text-muted" style="font-size:11px; margin-top:4px;">
                                Заполните это ЛИБО поле выше, не оба сразу. Не
                                требует покупки домена — только бесплатный
                                аккаунт Cloudflare (см.
                                <a href="https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/CfWorker.md"
                                   target="_blank" rel="noopener">CfWorker.md</a>).
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-grid" style="margin-top:16px;">
                    <div class="form-group">
                        <label>Профиль соединений</label>
                        <select id="tgws-resource-profile" class="form-control">
                            <option value="stealth" ${configuredPoolSize <= 1 ? "selected" : ""}>Low memory/stealth</option>
                            <option value="balanced" ${configuredPoolSize === 2 ? "selected" : ""}>Balanced</option>
                            <option value="latency" ${configuredPoolSize >= 4 ? "selected" : ""}>Low latency</option>
                        </select>
                        <div class="text-muted" style="font-size:11px; margin-top:4px;">
                            Stealth: pool 1/max 32; Balanced: 2/64; Low latency: 4/128.
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Состояние secret</label>
                        <div>${cfg.secret_configured ? "Настроен" : "Будет создан при сохранении"}</div>
                        <button class="btn btn-danger btn-sm" id="tgws-btn-rotate-secret" type="button">
                            Сменить secret
                        </button>
                    </div>
                </div>

                <div class="alert alert-warning" style="font-size:12px; margin-top:12px;">
                    Текущий upstream tg-ws-proxy-go использует
                    <code>InsecureSkipVerify</code> для исходящего WSS. GUI не скрывает
                    это ограничение: строгая TLS-проверка требует обновлённого upstream-бинарника.
                </div>

                <div id="tgws-mode-tunnel" class="mode-panel"
                     style="display:${currentMode === "tunnel" ? "block" : "none"}">
                    <div class="form-group">
                        <label>Туннель</label>
                        <select id="tgws-tunnel-select" class="form-control">
                            ${tunnelOptions}
                        </select>
                    </div>
                    <div class="alert alert-warning" style="font-size:12px; margin-top:8px;">
                        <strong>Важно понимать:</strong> при отказе этого
                        WARP-туннеля (например, Cloudflare заблокирует WireGuard/
                        MASQUE-подсети WARP в вашей стране) вы одновременно
                        потеряете и общий VPN через этот туннель, и обход
                        блокировки Telegram — это одна и та же инфраструктура,
                        а не независимый резерв. Если для вас важна отказоустойчивость
                        именно Telegram-обхода, надёжнее держать отдельный
                        CF-домен (режим выше) — он не зависит от состояния
                        вашего WARP-туннеля.
                    </div>
                </div>

                <div style="margin-top:16px; display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-primary" id="tgws-btn-save">Сохранить</button>
                    <button class="btn btn-success" id="tgws-btn-up">Запустить</button>
                    <button class="btn btn-danger" id="tgws-btn-down">Остановить</button>
                    <button class="btn" id="tgws-btn-restart">Перезапустить</button>
                </div>
            `;

            document.querySelectorAll('input[name="tgws-mode"]').forEach(r => {
                r.addEventListener("change", _onModeChange);
            });
            document.getElementById("tgws-btn-save").addEventListener(
                "click", _saveTgwsproxyConfig);
            document.getElementById("tgws-btn-up").addEventListener(
                "click", () => _tgwsAction("up"));
            document.getElementById("tgws-btn-down").addEventListener(
                "click", () => _tgwsAction("down"));
            document.getElementById("tgws-btn-restart").addEventListener(
                "click", () => _tgwsAction("restart"));
            document.getElementById("tgws-btn-rotate-secret").addEventListener(
                "click", _rotateSecret);

            await _loadTgwsproxyConnectInfo();
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    function _onModeChange(ev) {
        const mode = ev.target.value;
        ["direct", "cfcommunity", "cfdomain", "hybrid", "tunnel"].forEach(m => {
            const panel = document.getElementById(`tgws-mode-${m}`);
            if (panel) panel.style.display = (m === mode) ? "block" : "none";
        });
    }

    async function _saveTgwsproxyConfig() {
        const mode = document.querySelector('input[name="tgws-mode"]:checked').value;
        const port = parseInt(document.getElementById("tgws-port").value, 10) || 1443;
        const fakeTls = document.getElementById("tgws-fake-tls").value.trim();
        const dcIp = document.getElementById("tgws-dc-ip").value.trim();
        const resourceProfile = document.getElementById("tgws-resource-profile")?.value || "balanced";
        const resourceProfiles = {
            stealth: { pool_size: 1, max_conns: 32, buf_kb: 32 },
            balanced: { pool_size: 2, max_conns: 64, buf_kb: 64 },
            latency: { pool_size: 4, max_conns: 128, buf_kb: 128 },
        };
        const resources = resourceProfiles[resourceProfile] || resourceProfiles.balanced;

        let cfDomain = "", cfWorker = "";
        if (mode === "cfdomain") {
            cfDomain = document.getElementById("tgws-cf-domain").value.trim();
            cfWorker = document.getElementById("tgws-cf-worker").value.trim();
            if (cfDomain && cfWorker) {
                Toast.error("Заполните только одно поле — либо CF-домен, либо CF-Worker домен");
                return;
            }
            if (!cfDomain && !cfWorker) {
                Toast.error("Укажите CF-домен или CF-Worker домен для этого режима");
                return;
            }
        }

        try {
            // Сохраняем config.conf: в режиме "tunnel"/"direct" явно
            // очищаем cf_domain/cf_worker_domain, чтобы не оставался
            // рассинхронизированный конфиг (см. предупреждение в
            // документации функции: PUT — полная перезапись).
            const res = await API.put("/api/tgproxy/tgwsproxy/config", {
                port, fake_tls_domain: fakeTls,
                cf_domain: cfDomain, cf_worker_domain: cfWorker,
                dc_ip_default: dcIp,
                mode,
                ...resources,
            });
            if (!res.ok) {
                Toast.error(res.error || "Ошибка сохранения");
                return;
            }

            if (mode === "tunnel") {
                const sel = document.getElementById("tgws-tunnel-select");
                const val = sel ? sel.value : "";
                if (!val) {
                    Toast.error("Выберите туннель — нет доступных запущенных туннелей");
                    return;
                }
                const [kind, iface] = val.split("::");
                const tr = await API.post("/api/tgproxy/tgwsproxy/route-via-tunnel",
                    { kind, iface });
                if (!tr.ok) {
                    Toast.error(tr.error || "Не удалось настроить маршрут через туннель");
                    return;
                }
                Toast.success("Настройки сохранены, Telegram DC направлен через " +
                    kind + ":" + iface);
            } else {
                // direct / cfdomain — снимаем возможный оставшийся с
                // прошлого раза маршрут через туннель, если он был.
                await API.delete("/api/tgproxy/tgwsproxy/route-via-tunnel");
                Toast.success("Настройки сохранены" +
                    (cfDomain ? " — домен добавлен в nfqws2" : ""));
            }
            await _refresh();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _rotateSecret() {
        if (!confirm("Сменить secret? Все ранее выданные Telegram proxy links перестанут работать.")) return;
        try {
            const res = await API.post("/api/tgproxy/tgwsproxy/secret/rotate", { confirm: true });
            if (res.ok) {
                Toast.success("Secret сменён. Скопируйте новую ссылку подключения.");
                await _refresh();
            } else {
                Toast.error(res.error || "Не удалось сменить secret");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _tgwsAction(action) {
        try {
            const res = await API.post(`/api/tgproxy/tgwsproxy/${action}`);
            if (res.ok) {
                Toast.success({ up: "Запущен", down: "Остановлен",
                               restart: "Перезапущен" }[action]);
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _loadTgwsproxyConnectInfo() {
        const el = document.getElementById("tgwsproxy-connect");
        if (!el) return;
        try {
            const info = await API.get("/api/tgproxy/tgwsproxy/connect-info");
            if (!info.link) {
                el.innerHTML = `<div class="text-muted">Запустите прокси, чтобы получить ссылку подключения.</div>`;
                return;
            }
            el.innerHTML = `
                <div class="detail-row">Откройте на телефоне (в той же Wi-Fi сети):</div>
                <div class="connect-link">
                    <code id="tgws-link-text">${esc(info.link)}</code>
                    <button class="btn btn-sm" id="tgws-copy-link">Копировать</button>
                </div>
                ${info.fake_tls ? '<div class="text-muted" style="margin-top:6px;">Режим: Fake-TLS (ee)</div>' : ""}
            `;
            document.getElementById("tgws-copy-link").addEventListener("click", () => {
                navigator.clipboard.writeText(info.link).then(
                    () => Toast.success("Ссылка скопирована"),
                    () => Toast.error("Не удалось скопировать"));
            });
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    // ─────────────────────────── mtproto (резерв) ───────────────────────────

    async function _loadMtprotoPanel() {
        const el = document.getElementById("mtproto-panel");
        if (!el) return;
        try {
            const det = await API.get("/api/tgproxy/detect");
            if (!det.mtproto || !det.mtproto.installed) {
                el.innerHTML = `<div class="text-muted">tg-mtproxy-client не найден на роутере.</div>`;
                return;
            }
            const st = await API.get("/api/tgproxy/status");
            const running = !!(st.mtproto && st.mtproto.running);

            let connectHtml = "";
            if (running) {
                const info = await API.get("/api/tgproxy/mtproto/connect-info");
                if (info.link) {
                    connectHtml = `
                        <div class="detail-row" style="margin-top:8px;">Ссылка подключения:</div>
                        <div class="connect-link"><code>${esc(info.link)}</code></div>
                    `;
                }
            }

            el.innerHTML = `
                <div class="text-muted" style="margin-bottom:8px;">
                    Резервный вариант через community-relay. Использовать, если
                    tg-ws-proxy-go (включая Cloudflare-фоллбэк) перестал работать
                    целиком — самостоятельная от Cloudflare инфраструктура.
                </div>
                <button class="btn ${running ? 'btn-danger' : 'btn-success'}" id="mtp-btn-toggle">
                    ${running ? "Остановить" : "Запустить"}
                </button>
                ${connectHtml}
            `;
            document.getElementById("mtp-btn-toggle").addEventListener(
                "click", () => _mtprotoToggle(running));
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _mtprotoToggle(currentlyRunning) {
        try {
            const res = await API.post(
                currentlyRunning ? "/api/tgproxy/mtproto/down" : "/api/tgproxy/mtproto/up");
            if (res.ok) {
                Toast.success(currentlyRunning ? "Остановлен" : "Запущен");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    // ─────────────────────────── общее ───────────────────────────

    function _startPoll() {
        if (!_pollTimer) {
            _pollTimer = setInterval(_loadStatus, POLL_MS);
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

    return { render, destroy };
})();
