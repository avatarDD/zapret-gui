/**
 * update_checker.js — Страница Unified Update Checker.
 *
 * Проверка обновлений ВСЕХ бинарников за один запрос.
 */

const UpdateCheckerPage = (() => {
    let _pollTimer = null;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1>Обновления</h1>
                    <span class="page-subtitle">Проверка всех бинарников</span>
                </div>
                <div style="display:flex;gap:8px;">
                    <button class="btn btn-primary" id="uc-btn-check">Проверить обновления</button>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Результаты</div>
                    <div class="card-body" id="uc-results">
                        <p class="text-muted">Нажмите "Проверить обновления" для проверки.</p>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Фоновая проверка</div>
                    <div class="card-body" id="uc-daemon">Загрузка...</div>
                </div>
            </div>
        `;

        document.getElementById("uc-btn-check").onclick = _check;
        await _loadDaemon();
    }

    function destroy() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    }

    async function _check() {
        const el = document.getElementById("uc-results");
        if (el) el.innerHTML = `<div class="text-muted"><span class="spinner" style="width:14px;height:14px;border-width:2px;"></span> Проверка...</div>`;
        try {
            const data = await API.post("/api/updates/check");
            _renderResults(data);
        } catch (e) {
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    function _renderResults(data) {
        const el = document.getElementById("uc-results");
        if (!el) return;
        const results = data.results || [];
        if (!results.length) {
            el.innerHTML = `<p class="text-muted">Нет данных.</p>`;
            return;
        }

        const updatesCount = data.updates_count || 0;
        let header = '';
        if (updatesCount > 0) {
            header = `<div style="margin-bottom:12px;padding:8px 12px;background:var(--warning-bg,#fff3cd);border-radius:6px;font-weight:600;">
                Найдено обновлений: ${updatesCount}
            </div>`;
        } else {
            header = `<div style="margin-bottom:12px;padding:8px 12px;background:var(--success-bg,#d4edda);border-radius:6px;">
                Все бинарники актуальны
            </div>`;
        }

        let html = header + '<table class="table"><thead><tr>';
        html += '<th>Компонент</th><th>Установлен</th><th>Текущая</th><th>Последняя</th><th></th>';
        html += '</tr></thead><tbody>';

        for (const r of results) {
            const installedCls = r.installed ? "status-ok" : "status-off";
            const updateCls = r.has_update ? "status-warning" : "";
            html += `<tr>
                <td><strong>${esc(r.display_name || r.name)}</strong></td>
                <td><span class="status-dot ${installedCls}"></span> ${r.installed ? "Да" : "Нет"}</td>
                <td><code>${esc(r.current || "-")}</code></td>
                <td><code class="${updateCls}">${esc(r.latest || "-")}</code></td>
                <td>${r.has_update ? '<span style="color:var(--warning);font-weight:600;">← доступно</span>' : ""}
                    ${r.error ? '<span class="text-error" title="' + esc(r.error) + '">⚠</span>' : ""}
                </td>
            </tr>`;
        }
        html += '</tbody></table>';

        if (data.checked_at) {
            html += `<div class="text-muted" style="font-size:11px;margin-top:8px;">
                Проверено: ${new Date(data.checked_at * 1000).toLocaleString()}</div>`;
        }

        el.innerHTML = html;
    }

    async function _loadDaemon() {
        try {
            const st = await API.get("/api/updates/status");
            const el = document.getElementById("uc-daemon");
            if (!el) return;
            const cls = st.running ? "status-ok" : "status-off";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${st.running ? "Фоновая проверка активна" : "Фоновая проверка выключена"}</span>
                </div>
                <p class="text-muted" style="font-size:12px;margin-top:8px;">
                    Фоновая проверка запускается раз в 24 часа и логирует найденные обновления.
                </p>
            `;
        } catch (e) {
            const el = document.getElementById("uc-daemon");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy };
})();
