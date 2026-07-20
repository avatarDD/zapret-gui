/**
 * block_detector.js — Страница Block Detector.
 *
 * DNS-мониторинг + автообнаружение блокировок.
 * Показывает результаты probing доменов, управление детектором.
 */

const BlockDetectorPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 5000;

    let _visibilityHandler = null;
    let _inFlight = false;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Block Detector${typeof Help !== 'undefined' ? Help.button('block-detector') : ''}</h1>
                <span class="page-subtitle">DNS-мониторинг + автообнаружение блокировок</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="bd-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Ручная проверка</div>
                    <div class="card-body">
                        <div class="form-inline">
                            <input type="text" id="bd-probe-domain" class="form-control"
                                   placeholder="example.com" style="flex:1">
                            <button class="btn btn-primary" id="bd-btn-probe">Проверить</button>
                        </div>
                        <div id="bd-probe-result" style="margin-top:8px"></div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Результаты проверок</div>
                    <div class="card-body" id="bd-results">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Управление</div>
                    <div class="card-body">
                        <button class="btn btn-primary" id="bd-btn-start">Запустить мониторинг</button>
                        <button class="btn btn-danger" id="bd-btn-stop">Остановить</button>
                        <button class="btn" id="bd-btn-refresh">Обновить</button>
                    </div>
                </div>
            </div>
        `;

        document.getElementById("bd-btn-probe").onclick = _probe;
        document.getElementById("bd-btn-start").onclick = _start;
        document.getElementById("bd-btn-stop").onclick = _stop;
        document.getElementById("bd-btn-refresh").onclick = _refresh;

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
            await Promise.all([_loadStatus(), _loadResults()]);
        } finally {
            _inFlight = false;
        }
    }

    async function _loadStatus() {
        try {
            const st = await API.get("/api/block-detector/status");
            const el = document.getElementById("bd-status");
            if (!el) return;
            const cls = st.running ? "status-ok" : "status-off";
            const text = st.running ? "Работает" : "Остановлен";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                </div>
                <div class="detail-row">Отслеживается доменов: <strong>${st.monitored_count || 0}</strong></div>
                <div class="detail-row">Заблокировано: <strong>${st.blocked_count || 0}</strong></div>
            `;
        } catch (e) {
            const el = document.getElementById("bd-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _loadResults() {
        try {
            const data = await API.get("/api/block-detector/results");
            const el = document.getElementById("bd-results");
            if (!el) return;
            const results = data.results || [];
            if (!results.length) {
                el.innerHTML = `<p class="text-muted">Пока нет результатов. Запустите мониторинг или проверьте домен вручную.</p>`;
                return;
            }
            let html = '<table class="table"><thead><tr>';
            html += '<th>Домен</th><th>Статус</th><th>Описание</th><th>Последняя проверка</th>';
            html += '</tr></thead><tbody>';
            for (const r of results) {
                const cls = r.block_code === "ok" ? "status-ok" : "status-error";
                const timeStr = r.last_checked ? _timeAgo(r.last_checked) : "never";
                html += `<tr>
                    <td><code>${esc(r.domain)}</code></td>
                    <td><span class="status-dot ${cls}"></span> ${esc(r.block_code)}</td>
                    <td>${esc(r.block_desc)}</td>
                    <td>${timeStr}</td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;
        } catch (e) {
            const el = document.getElementById("bd-results");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _probe() {
        const domain = document.getElementById("bd-probe-domain").value.trim();
        if (!domain) return;
        const el = document.getElementById("bd-probe-result");
        el.innerHTML = `<span class="text-muted">Проверка ${esc(domain)}...</span>`;
        try {
            const res = await API.post("/api/block-detector/probe", { domain });
            const cls = res.block_code === "ok" ? "status-ok" : "status-error";
            el.innerHTML = `
                <span class="status-dot ${cls}"></span>
                <strong>${esc(domain)}</strong> → ${esc(res.block_code)}
                <span class="text-muted">(${esc(res.block_desc)})</span>
            `;
            await _loadResults();
        } catch (e) {
            el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _start() {
        try {
            await API.post("/api/block-detector/start");
            Toast.success("Мониторинг запущен");
            await _refresh();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function _stop() {
        try {
            await API.post("/api/block-detector/stop");
            Toast.success("Мониторинг остановлен");
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

    function _timeAgo(ts) {
        const diff = Math.floor(Date.now() / 1000) - ts;
        if (diff < 60) return _t("seconds_ago", { diff });
        if (diff < 3600) return _t("minutes_ago", { diff: Math.floor(diff / 60) });
        if (diff < 86400) return _t("hours_ago", { diff: Math.floor(diff / 3600) });
        return _t("days_ago", { diff: Math.floor(diff / 86400) });
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy };
})();
