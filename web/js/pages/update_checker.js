/**
 * update_checker.js — Страница Unified Update Checker.
 *
 * Проверка обновлений ВСЕХ бинарников за один запрос.
 */

const UpdateCheckerPage = (() => {
    let _pollTimer = null;

    // Куда вести за установкой/обновлением каждого компонента.
    // Имена — те же, что отдаёт /api/updates (см. core/update_checker).
    //
    // Оба Telegram-движка живут на ОДНОЙ странице, поэтому им нужен
    // ?focus=<движок>: без него нажатие «Установить» напротив
    // tg-mtproxy-client открывало страницу на панели tg-ws-proxy-go, и
    // выглядело это как «не та программа и без кнопки установки»
    // (issue #272).
    const _PAGES = {
        "zapret2":   "zapret",
        "gui":       "zapret",        // обновление GUI живёт там же
        "awg":       "awg-setup",
        "singbox":   "singbox-setup",
        "mihomo":    "mihomo-setup",
        "usque":     "usque-setup",
        "tgwsproxy": "tgproxy?focus=tgwsproxy",
        "tgproto":   "tgproxy?focus=mtproto",
        "opera":     "opera-proxy",
    };

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1>Обновления${typeof Help !== 'undefined' ? Help.button('updates') : ''}</h1>
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
        // Показываем ранее закешированные результаты сразу при открытии.
        try {
            const cached = await API.get("/api/updates");
            if (cached && (cached.results || []).length) _renderResults(cached);
        } catch (_) {}
        await _loadDaemon();
    }

    function destroy() {
        if (_pollTimer) { clearTimeout(_pollTimer); _pollTimer = null; }
    }

    async function _check() {
        const btn = document.getElementById("uc-btn-check");
        const el  = document.getElementById("uc-results");
        if (btn) { btn.disabled = true; btn.textContent = "Проверка..."; }
        if (el) el.innerHTML = `<div class="text-muted"><span class="spinner" style="width:14px;height:14px;border-width:2px;"></span> Проверка...</div>`;
        try {
            // POST /check запускает проверку в фоне (не возвращает результаты),
            // затем поллим статус до завершения и читаем кеш /api/updates.
            await API.post("/api/updates/check");
            await _pollUntilDone();
        } catch (e) {
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
            if (btn) { btn.disabled = false; btn.textContent = "Проверить обновления"; }
        }
    }

    // Поллинг статуса до checking=false, затем рендер кешированных результатов.
    function _pollUntilDone() {
        const btn = document.getElementById("uc-btn-check");
        const started = Date.now();
        const MAX_MS = 90000;  // защита от вечного ожидания
        return new Promise((resolve) => {
            async function tick() {
                let checking = false;
                try {
                    const st = await API.get("/api/updates/status");
                    checking = !!st.checking;
                } catch (_) { checking = false; }

                if (!checking || (Date.now() - started) > MAX_MS) {
                    _pollTimer = null;
                    try {
                        const data = await API.get("/api/updates");
                        _renderResults(data);
                    } catch (e) {
                        const el = document.getElementById("uc-results");
                        if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
                    }
                    if (btn) { btn.disabled = false; btn.textContent = "Проверить обновления"; }
                    resolve();
                    return;
                }
                _pollTimer = setTimeout(tick, 2000);
            }
            // первый опрос — с небольшой задержкой, дать фоновой проверке стартовать
            _pollTimer = setTimeout(tick, 1500);
        });
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
            // Установка/обновление у каждого компонента своя (со своим
            // прогрессом и проверкой SHA256), поэтому ведём на его
            // страницу, а не дублируем инсталлятор здесь. Раньше строка
            // сообщала «← доступно» и на этом всё — куда идти дальше,
            // пользователь должен был догадываться сам.
            const page = _PAGES[r.name] || "";
            const action = page
                ? `<button class="btn btn-sm ${r.has_update ? "btn-primary" : ""}"
                           data-page="${esc(page)}">
                       ${r.has_update ? "Обновить" : (r.installed ? "Открыть" : "Установить")}
                   </button>`
                : "";
            html += `<tr>
                <td><strong>${esc(r.display_name || r.name)}</strong></td>
                <td${r.path ? ` title="${esc(r.path)}"` : ""}><span class="status-dot ${installedCls}"></span> ${r.installed ? "Да" : "Нет"}</td>
                <td><code>${esc(r.current || "-")}</code></td>
                <td><code class="${updateCls}">${esc(r.latest || "-")}</code></td>
                <td>${r.has_update ? '<span style="color:var(--warning);font-weight:600;">← доступно</span>' : ""}
                    ${r.error ? '<span class="text-error" title="' + esc(r.error) + '">⚠</span>' : ""}
                    ${action}
                </td>
            </tr>`;
        }
        html += '</tbody></table>';

        if (data.checked_at) {
            html += `<div class="text-muted" style="font-size:11px;margin-top:8px;">
                Проверено: ${new Date(data.checked_at * 1000).toLocaleString()}</div>`;
        }

        el.innerHTML = html;
        el.querySelectorAll("button[data-page]").forEach(b => {
            b.addEventListener("click", (e) => {
                window.location.hash = e.currentTarget.getAttribute("data-page");
            });
        });
    }

    async function _loadDaemon() {
        try {
            const st = await API.get("/api/updates/status");
            const el = document.getElementById("uc-daemon");
            if (!el) return;
            // Интервал и флаг включения читаем из настроек: раньше в
            // тексте стояло жёсткое «раз в 24 часа», а включить/выключить
            // проверку из GUI было нечем — ручки /start и /stop
            // существовали, но ни одна кнопка их не вызывала.
            let enabled = false, interval = 24;
            try {
                const cfg = await API.get("/api/config");
                const uc = (cfg && cfg.config && cfg.config.update_checker) || {};
                enabled = !!uc.enabled;
                interval = uc.interval_hours || 24;
            } catch (_) { /* останемся на значениях по умолчанию */ }

            const cls = st.running ? "status-ok" : "status-off";
            el.innerHTML = `
                <div class="status-row">
                    <span class="status-dot ${cls}"></span>
                    <span>${st.running ? "Фоновая проверка активна" : "Фоновая проверка выключена"}</span>
                </div>
                ${st.stale_check ? `<div class="form-hint" style="color:var(--warning);">
                    Последняя проверка не удалась — показаны данные с прошлого раза.
                    Проверьте доступ к api.github.com.
                </div>` : ""}

                <div class="form-group" style="margin-top:12px;">
                    <label class="form-label" style="display:flex; align-items:center; gap:8px;">
                        <input type="checkbox" id="uc-enabled" ${enabled ? "checked" : ""}>
                        Проверять обновления в фоне
                    </label>
                    <div class="form-hint">
                        GUI сам сходит за версиями по расписанию и запишет находки
                        в лог. Ничего не устанавливает — обновление вы запускаете
                        сами кнопкой в таблице выше.
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="uc-interval">Интервал, часов</label>
                    <input type="number" id="uc-interval" class="form-control"
                           min="1" max="720" value="${esc(String(interval))}"
                           style="max-width:140px;">
                    <div class="form-hint">
                        Минимум 1 час. Один проход — около девяти обращений к API
                        GitHub, а без токена там лимит 60 запросов в час, поэтому
                        чаще смысла нет.
                    </div>
                </div>

                <button class="btn btn-primary btn-sm" id="uc-save">Сохранить</button>
            `;
            document.getElementById("uc-save").addEventListener("click", _saveDaemon);
        } catch (e) {
            const el = document.getElementById("uc-daemon");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    async function _saveDaemon() {
        const enabled = document.getElementById("uc-enabled").checked;
        let interval = parseInt(document.getElementById("uc-interval").value, 10);
        if (!Number.isFinite(interval) || interval < 1) interval = 24;
        if (interval > 720) interval = 720;
        try {
            await API.put("/api/config",
                          { update_checker: { enabled, interval_hours: interval } });
            // Демон читает конфиг только на старте цикла, поэтому явно
            // переводим его в нужное состояние.
            await API.post(enabled ? "/api/updates/start" : "/api/updates/stop");
            Toast.success(enabled
                ? `Фоновая проверка включена, раз в ${interval} ч`
                : "Фоновая проверка выключена");
            await _loadDaemon();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy };
})();
