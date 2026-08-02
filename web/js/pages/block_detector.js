/**
 * block_detector.js — вкладка «Мониторинг DNS» раздела «Диагностика блокировок».
 *
 * Фоновой детектор: следит за DNS-запросами клиентов, сам пронирует новые
 * домены и (опционально) складывает заблокированные в named list.
 *
 * Заголовок раздела и вкладки рисует BlockcheckHubPage. Вердикты приходят с
 * бэкенда в той же таксономии, что и у «Теста доступности» (общая проба —
 * core/testers/probe.py), поэтому здесь показывается и способ обхода.
 */

const BlockDetectorPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 5000;

    let _visibilityHandler = null;
    let _inFlight = false;

    // Подписи способа обхода — те же формулировки, что на вкладке «Тест».
    const REMEDIATION = {
        zapret:  { text: 'Обход DPI (zapret)', cls: 'rem-zapret' },
        tunnel:  { text: 'Нужен туннель',      cls: 'rem-tunnel' },
        dns:     { text: 'Настроить DNS',      cls: 'rem-dns' },
        none:    { text: 'Обход не нужен',     cls: 'rem-none' },
        unknown: { text: '—',                  cls: 'rem-skip' },
    };

    function _remBadge(rem) {
        const r = REMEDIATION[rem] || REMEDIATION.unknown;
        return `<span class="bc-chip ${r.cls}" style="font-size:10px;padding:1px 7px;">${r.text}</span>`;
    }

    async function render(container) {
        container.innerHTML = `
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
                        <div class="form-hint" style="margin-top:6px;">
                            Быстрая проба одного домена: DNS → TCP:443 → TLS → HTTP.
                            Нужен полный разбор (QUIC, ClientHello, CDN, traceroute) —
                            вкладка «Тест доступности».
                        </div>
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
            // Детектор не берёт домены из списка — он подсматривает живые
            // DNS-запросы. Без этой подписи «отслеживается 0» выглядело как
            // поломка, хотя чаще всего источник просто недоступен.
            const NAMES = {
                dnsmasq_log: "лог dnsmasq (/var/log/dnsmasq.log)",
                adguard_log: "лог AdGuard Home",
                af_packet:   "перехват DNS-пакетов (AF_PACKET)",
            };
            function _sourceHtml(s) {
                if (!s.dns_source) return "";
                const name = NAMES[s.dns_source] || s.dns_source;
                if (s.dns_source_available) {
                    return `<div class="form-hint" style="margin-top:6px;">
                        Источник доменов: ${name}. Список наполняется сам, по мере
                        того как клиенты обращаются к сайтам — сразу после запуска
                        он пуст, это нормально.
                    </div>`;
                }
                return `<div class="form-hint" style="margin-top:6px; color:var(--warning);">
                    Источник доменов недоступен: ${name}. Мониторинг запустится,
                    но список так и останется пустым. Нужен либо dnsmasq с
                    включённым логом запросов, либо AdGuard Home, либо запуск
                    GUI от root (для перехвата пакетов).
                </div>`;
            }
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${text}</span>
                </div>
                <div class="detail-row">Отслеживается доменов: <strong>${st.monitored_count || 0}</strong></div>
                <div class="detail-row">Заблокировано: <strong>${st.blocked_count || 0}</strong>,
                    из них с понятным обходом: <strong>${st.actionable_count || 0}</strong></div>
                ${_sourceHtml(st)}
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
            html += '<th>Домен</th><th>Статус</th><th>Описание</th><th>Обход</th>'
                 + '<th>Последняя проверка</th><th></th>';
            html += '</tr></thead><tbody>';
            for (const r of results) {
                const cls = r.block_code === "ok" ? "status-ok" : "status-error";
                const timeStr = r.last_checked ? _timeAgo(r.last_checked) : "never";
                const detail = r.detail
                    ? `<div class="text-muted" style="font-size:11px;">${esc(r.detail)}</div>` : '';
                html += `<tr>
                    <td><code>${esc(r.domain)}</code></td>
                    <td><span class="status-dot ${cls}"></span> ${esc(r.block_code)}</td>
                    <td>${esc(r.block_desc)}${detail}</td>
                    <td>${_remBadge(r.remediation)}</td>
                    <td>${timeStr}</td>
                    <td><button class="btn btn-ghost btn-sm" data-deep="${esc(r.domain)}"
                                title="Разобрать домен на вкладке «Тест доступности»">Разобрать</button></td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;
            el.querySelectorAll('button[data-deep]').forEach(btn => {
                btn.onclick = () => {
                    if (typeof BlockcheckHubPage !== 'undefined') {
                        BlockcheckHubPage.deepCheck(btn.dataset.deep);
                    }
                };
            });
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
            if (res.ok === false) {
                el.innerHTML = `<div class="text-error">${esc(res.error || 'Ошибка проверки')}</div>`;
                return;
            }
            const cls = res.block_code === "ok" ? "status-ok" : "status-error";
            const detail = res.detail
                ? `<div class="text-muted" style="font-size:11px;">${esc(res.detail)}</div>` : '';
            el.innerHTML = `
                <span class="status-dot ${cls}"></span>
                <strong>${esc(domain)}</strong> → ${esc(res.block_code)}
                <span class="text-muted">(${esc(res.block_desc)})</span>
                ${_remBadge(res.remediation)}
                ${detail}
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
