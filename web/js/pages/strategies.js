/**
 * strategies.js — Страница стратегий.
 *
 * Список стратегий (карточки), применение, редактор,
 * превью итоговой команды nfqws2, избранное.
 */

const StrategiesPage = (() => {
    let strategies = [];
    let currentId = null;
    let favorites = [];
    let pollTimer = null;
    let hostlistFiles = [];  // [{name, filename, path, is_builtin}] — для дропдауна в редакторе
    let pendingPrefill = null;  // стратегия из blockcheck2-бейджа, открыть после навигации

    // §3/§4/§5/§7 — буфер обмена, ESC, ресайз окна, массовое объединение.
    let selectedIds = new Set();   // выделенные карточки для объединения (§7)
    let editorOnSaved = null;      // коллбэк после успешного сохранения редактора
    let escKeyHandler = null;      // document keydown (ESC) — закрыть редактор/превью (§4)
    let pasteHandler = null;       // document paste (Ctrl+V) — вставка стратегии (§3)
    let modalResize = null;        // активный ресайзер окна редактора (§5)

    // IDE-редактор: активный профиль и позиция курсора — чтобы боковая панель
    // показывала подсказку по токену под курсором именно в нём.
    let editorActive = { index: 0, cursor: 0 };

    // Пресеты «+ фильтр…» — значения согласованы с дефолтами ScanTarget и
    // авто-обёрткой бэкенда (SKILL §3). Вставляются в НАЧАЛО args профиля.
    const FILTER_PRESETS = {
        tls443: '--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello',
        http80: '--filter-tcp=80 --filter-l7=http --payload=http_req',
        quic443: '--filter-udp=443 --filter-l7=quic --payload=quic_initial',
    };

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">Стратегии${typeof Help !== 'undefined' ? Help.button('strategies') : ''}</h1>
                    <p class="page-description">Управление стратегиями desync для nfqws2</p>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-ghost" id="strat-update-btn" onclick="StrategiesPage.updateCatalog()" title="Обновить каталог стратегий из youtubediscord/zapret">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23 4 23 10 17 10"/>
                            <polyline points="1 20 1 14 7 14"/>
                            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/>
                            <path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/>
                        </svg>
                        <span id="strat-update-btn-label">Обновить стратегии</span>
                    </button>
                    <button class="btn btn-ghost" onclick="StrategiesPage.pasteStrategyFromClipboard()" title="Вставить стратегию из буфера обмена (или Ctrl+V на странице) — откроется создание новой стратегии с профилями из буфера">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
                            <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
                        </svg>
                        Вставить из буфера
                    </button>
                    <button class="btn btn-primary" onclick="StrategiesPage.openCreate()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                        </svg>
                        Создать стратегию
                    </button>
                </div>
            </div>

            <!-- Статус каталога стратегий -->
            <div class="card" id="catalog-status-card" style="display:none;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    Каталог стратегий
                </div>
                <div id="catalog-status-body" style="font-size:13px; color:var(--text-muted);">
                    Загрузка...
                </div>
            </div>

            <!-- Активная стратегия -->
            <div class="card" id="active-strategy-card" style="border-left: 3px solid var(--success);">
                <div class="card-title" style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
                    <span style="display:flex; align-items:center; gap:6px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                        </svg>
                        Активная стратегия
                    </span>
                    <span style="display:flex; align-items:center; gap:12px;">
                        <label class="toggle-label" id="nfqws-debug-label" style="display:flex; align-items:center; gap:6px; font-size:12px; font-weight:400; color:var(--text-muted); cursor:pointer;" title="Режим отладки nfqws2 (--debug): пер-пакетный лог в журнал — грузятся ли lua, объявлены ли блобы, матчится ли пакет цели, какие desync применяются. Применяется сразу (если nfqws2 запущен — перезапустится).">
                            <input type="checkbox" id="nfqws-debug-toggle" onchange="StrategiesPage.toggleDebug(this.checked)">
                            🐞 Отладка nfqws2
                        </label>
                        <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.openLogs()" title="Открыть журнал (логи nfqws2) — там виден пер-пакетный вывод при включённой отладке" style="font-size:12px; font-weight:400;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" style="margin-right:4px;">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
                            </svg>
                            Журнал
                        </button>
                    </span>
                </div>
                <div id="active-strategy-info" style="display:flex; align-items:center; gap:12px;">
                    <span class="text-muted">Загрузка...</span>
                </div>
            </div>

            <!-- Авто-починка (Healthcheck): фоновый watchdog сбрасывает
                 выученные стратегии при провалах референс-доменов. -->
            <div class="card" id="healthcheck-card">
                <div class="card-title" style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                    <span style="display:flex; align-items:center; gap:6px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                        </svg>
                        Авто-починка (healthcheck)
                        <span class="text-muted" style="font-size:12px; font-weight:400;">проверяет связь и обновляет circular при провалах</span>
                    </span>
                    <span style="display:flex; align-items:center; gap:8px;">
                        <label class="toggle-label" style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer;" title="Когда включено, демон каждые N минут проверяет YouTube/Discord/Telegram и при N провалах подряд сбрасывает выученную circular-стратегию (чтобы nfqws2 переподобрал её для затронутого домена).">
                            <input type="checkbox" id="healthcheck-toggle" onchange="StrategiesPage.toggleHealthcheck(this.checked)">
                            <span id="healthcheck-toggle-label">Включить</span>
                        </label>
                        <button class="btn btn-ghost btn-sm" id="healthcheck-run-btn" onclick="StrategiesPage.runHealthcheckNow()" title="Прогнать проверку прямо сейчас (без ожидания таймера). Проверка идёт ~10–30 сек.">
                            <svg class="btn-icon" id="healthcheck-run-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polygon points="5 3 19 12 5 21 5 3"/>
                            </svg>
                            <span id="healthcheck-run-label">Проверить сейчас</span>
                        </button>
                        <button class="btn btn-ghost btn-sm" id="healthcheck-cfg-btn" onclick="StrategiesPage.toggleHealthcheckSettings()" title="Настроить: какие сайты проверять, контрольный сайт, пороги">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <circle cx="12" cy="12" r="3"/>
                                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                            </svg>
                            Настроить
                        </button>
                    </span>
                </div>
                <div class="text-muted" style="font-size:12px; line-height:1.5; margin-bottom:10px; padding:8px 10px; background:var(--bg-secondary, rgba(127,127,127,.08)); border-radius:6px;">
                    Демон периодически проверяет доступность сайтов. Если сайт
                    перестал открываться — сбрасывает «выученную» стратегию для
                    него, и обход (circular) подберёт рабочую заново.
                    <b>Полезно</b>, если используете авто-стратегию (circular) и
                    хотите, чтобы обход сам восстанавливался без вашего участия.
                    Кнопка «Проверить сейчас» работает и при выключенном демоне.
                </div>
                <div id="healthcheck-settings" style="display:none; margin-bottom:12px;"></div>
                <div id="healthcheck-body" style="font-size:13px;">
                    <span class="text-muted">Загрузка...</span>
                </div>
            </div>

            <!-- Выученные стратегии (z2k-state-persist autocircular) -->
            <div class="card" id="autocircular-state-card">
                <div class="card-title" style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                    <span style="display:flex; align-items:center; gap:6px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M12 2v4"/><path d="M12 18v4"/>
                            <path d="M4.93 4.93l2.83 2.83"/><path d="M16.24 16.24l2.83 2.83"/>
                            <path d="M2 12h4"/><path d="M18 12h4"/>
                            <path d="M4.93 19.07l2.83-2.83"/><path d="M16.24 7.76l2.83-2.83"/>
                        </svg>
                        Выученные стратегии (autocircular)
                        <span class="text-muted" style="font-size:12px; font-weight:400;">circular подобрал и закрепил</span>
                    </span>
                    <span style="display:flex; align-items:center; gap:8px;">
                        <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.refreshState()" title="Обновить из файла state.tsv">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/>
                                <path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/>
                            </svg>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="StrategiesPage.clearAllState()" title="Сбросить все выученные стратегии. После сброса circular переберёт стратегии заново для каждого нового потока.">
                            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/>
                            </svg>
                            Сбросить всё
                        </button>
                    </span>
                </div>
                <div id="autocircular-state-body" style="font-size:13px;">
                    <span class="text-muted">Загрузка...</span>
                </div>
            </div>

            <!-- Список стратегий (ListUI рендерит свой поиск/фильтры/пагинацию) -->
            <div id="strategies-list-host">
                <div class="text-muted" style="text-align:center; padding:32px;">
                    <div class="spinner" style="margin:0 auto 12px;"></div>
                    Загрузка стратегий...
                </div>
            </div>

            <!-- Панель массовых действий (объединение выбранных стратегий) -->
            <div id="strat-bulkbar" class="strat-bulkbar" style="display:none;"></div>

            <!-- Модальное окно: редактор стратегии -->
            <div id="strategy-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title" id="modal-title">Создать стратегию</h3>
                        <button class="modal-close" onclick="StrategiesPage.closeModal()">&times;</button>
                    </div>
                    <div class="modal-body" id="modal-body">
                        <!-- Заполняется динамически -->
                    </div>
                </div>
            </div>

            <!-- Модальное окно: превью команды -->
            <div id="preview-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title">Превью команды nfqws2</h3>
                        <button class="modal-close" onclick="StrategiesPage.closePreview()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="log-viewer nfq-resizable" id="preview-command" style="height:340px; white-space:pre-wrap; word-break:break-all; font-size:12px; line-height:1.6; padding:16px;">
                            Загрузка...
                        </div>
                        <div id="preview-validation" style="display:none; margin-top:12px;"></div>
                        <div style="margin-top:12px; display:flex; justify-content:space-between; align-items:center; gap:8px;">
                            <button class="btn btn-primary" id="preview-validate-btn" onclick="StrategiesPage.validatePreview()" title="Проверить стратегию через nfqws2 --intercept=0 (грузит lua-init, без поднятия NFQUEUE и трафика)">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M9 11l3 3L22 4"/>
                                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                                </svg>
                                Проверить
                            </button>
                            <button class="btn btn-ghost" onclick="StrategiesPage.copyPreview()">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                </svg>
                                Копировать
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        fetchStrategies();
        refreshCatalogStatus();
        refreshDebugToggle();
        refreshState();
        refreshHealthcheck();
        // ESC закрывает редактор/превью (§4), Ctrl+V на странице вставляет
        // стратегию из буфера (§3).
        attachGlobalKeys();
        renderBulkBar();
        // Если пришли сюда из blockcheck2-бейджа — открыть редактор с приёмом.
        consumePendingPrefill();
    }

    // ══════════════════ Healthcheck (autocircular watchdog) ══════════════════

    async function refreshHealthcheck() {
        const body = document.getElementById('healthcheck-body');
        if (!body) return;
        try {
            const data = await API.get('/api/healthcheck/status');
            if (!data || !data.ok) return;
            renderHealthcheckBody(data.status || {});
        } catch (_e) {
            body.innerHTML = '<span class="text-muted">Сервис недоступен</span>';
        }
    }

    function renderHealthcheck(st) {
        const fmtTs = (ts) => {
            if (!ts) return '—';
            try { return new Date(ts * 1000).toLocaleString(); }
            catch (_) { return ts; }
        };
        const summary = st.last_summary;
        const threshold = st.consecutive_failures || 2;

        // Идёт проверка прямо сейчас — показываем спиннер.
        if (st.checking) {
            return `<div style="display:flex; align-items:center; gap:10px; padding:10px 0; color:var(--text-muted);">
                <div class="spinner" style="width:18px; height:18px;"></div>
                Проверяю доступность сайтов… (до ~30 секунд)
            </div>` + cfgLine(st);
        }

        let summaryHtml = '';
        if (summary && summary.total) {
            let statusBadge;
            if (summary.global_outage) {
                statusBadge = '<span class="badge badge-danger" title="Упали все сайты — похоже на отсутствие связи или nfqws2 не запущен">нет связи?</span>';
            } else if (summary.failed === 0) {
                statusBadge = '<span class="badge badge-success">все OK</span>';
            } else {
                statusBadge = `<span class="badge badge-warning">${summary.ok}/${summary.total} работает</span>`;
            }
            summaryHtml = `
                <div style="display:flex; gap:8px; align-items:center; margin-bottom:8px; flex-wrap:wrap;">
                    <span class="text-muted" style="font-size:12px;">Последняя: ${escapeHtml(fmtTs(summary.ts))}</span>
                    ${statusBadge}
                    ${(st.running && st.next_check_at) ? `<span class="text-muted" style="font-size:12px;">следующая: ${escapeHtml(fmtTs(st.next_check_at))}</span>` : ''}
                </div>
            `;
        }

        // Баннер «глобального обвала» — объясняем, почему сброса не было.
        let outageHtml = '';
        if (summary && summary.global_outage) {
            const ctl = summary.control_domain;
            const ctlNote = ctl
                ? `Контрольный сайт <code>${escapeHtml(ctl)}</code> тоже недоступен — связи, похоже, нет.`
                : `Контрольный сайт не задан, поэтому падение всех сайтов считается обвалом.`;
            outageHtml = `<div style="font-size:12px; line-height:1.5; margin-bottom:8px; padding:8px 10px; border-radius:6px; background:rgba(248,113,113,.12); border-left:3px solid var(--danger, #f87171);">
                ⚠ Не открылся ни один сайт, поэтому выученные стратегии
                <b>не сбрасывались</b>. ${ctlNote}
                <div style="margin-top:4px;">Если у вас <b>реально</b> бывает, что все сайты заблокированы
                одновременно — задайте «контрольный сайт» в
                <a href="#" onclick="StrategiesPage.toggleHealthcheckSettings(); return false;">настройках</a>
                (тогда при живой связи сброс будет срабатывать) или отключите
                там же «защиту от обвала».</div>
            </div>`;
        }

        const history = st.history || [];
        const last = history.length ? history[history.length - 1] : null;
        let resultsHtml = '';
        if (last && last.results && last.results.length) {
            const rows = last.results.map(r => {
                const okIcon = r.ok
                    ? '<span class="badge badge-success" style="font-size:11px;">OK</span>'
                    : '<span class="badge badge-danger" style="font-size:11px;">FAIL</span>';
                const rt = r.response_time ? `${r.response_time} ms` : '—';
                // Код ответа или короткая ошибка.
                let detail = '';
                if (r.ok) {
                    detail = r.status_code ? String(r.status_code) : '';
                } else if (r.error) {
                    detail = escapeHtml(String(r.error).slice(0, 50));
                } else if (r.status_code) {
                    detail = String(r.status_code);
                }
                // Сброс state или прогресс к нему.
                let reset = '';
                if ((r.hosts_reset || []).length) {
                    reset = r.hosts_reset.map(h =>
                        `<span class="badge badge-warning" style="font-size:11px;" title="Выученная стратегия сброшена для ${escapeHtml(h.host)} — circular переподберёт">↻ сброшено</span>`
                    ).join(' ');
                } else if (!r.ok && !summary.global_outage && r.fail_streak) {
                    reset = `<span class="text-muted" style="font-size:11px;" title="При ${threshold} провалах подряд выученная стратегия сбросится автоматически">провал ${r.fail_streak}/${threshold}</span>`;
                }
                return `
                    <tr>
                        <td><span style="margin-right:4px;">${escapeHtml(r.icon || '')}</span><strong>${escapeHtml(r.display || r.service)}</strong></td>
                        <td>${okIcon}</td>
                        <td class="text-muted" style="font-size:12px;">${escapeHtml(rt)}</td>
                        <td class="text-muted" style="font-size:12px;">${detail}</td>
                        <td>${reset}</td>
                    </tr>
                `;
            }).join('');
            resultsHtml = `
                <div style="overflow-x:auto;">
                    <table class="data-table" style="width:100%; font-size:13px;">
                        <thead>
                            <tr>
                                <th>Сайт</th>
                                <th>Статус</th>
                                <th>Время</th>
                                <th>Ответ</th>
                                <th>Авто-починка</th>
                            </tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            `;
        } else if (!st.enabled) {
            resultsHtml = `<div class="text-muted" style="padding:8px 0;">
                Демон выключен. Нажмите «Проверить сейчас» для разовой проверки
                или включите автоматический режим переключателем.
            </div>`;
        } else {
            resultsHtml = `<div class="text-muted" style="padding:8px 0;">Демон запущен, первая проверка скоро выполнится (через ~30 сек после старта).</div>`;
        }
        return summaryHtml + outageHtml + resultsHtml + cfgLine(st);
    }

    function cfgLine(st) {
        return `
            <div class="text-muted" style="font-size:11px; margin-top:6px;">
                Интервал: ${st.interval_min || 5} мин · Сайтов: ${(st.services || []).length}
                · Сброс после: ${st.consecutive_failures || 2} провалов подряд
                · Авто-сброс: ${st.auto_reset ? 'вкл' : 'выкл'}
            </div>
        `;
    }

    async function toggleHealthcheck(on) {
        const toggle = document.getElementById('healthcheck-toggle');
        try {
            const endpoint = on ? '/api/healthcheck/enable' : '/api/healthcheck/disable';
            const data = await API.post(endpoint, {});
            if (data && data.ok) {
                Toast.success(on ? 'Авто-починка включена' : 'Авто-починка выключена');
                refreshHealthcheck();
            } else {
                Toast.error((data && data.error) || 'Не удалось переключить');
                if (toggle) toggle.checked = !on;
            }
        } catch (err) {
            Toast.error(err.message);
            if (toggle) toggle.checked = !on;
        }
    }

    let healthcheckPollTimer = null;

    function setRunBtnLoading(loading) {
        const btn = document.getElementById('healthcheck-run-btn');
        const label = document.getElementById('healthcheck-run-label');
        const icon = document.getElementById('healthcheck-run-icon');
        if (!btn) return;
        btn.disabled = loading;
        if (label) label.textContent = loading ? 'Проверяю…' : 'Проверить сейчас';
        if (icon) icon.style.display = loading ? 'none' : '';
    }

    async function runHealthcheckNow() {
        // Защита от двойного клика
        const btn = document.getElementById('healthcheck-run-btn');
        if (btn && btn.disabled) return;

        try {
            setRunBtnLoading(true);
            // Неблокирующий запуск: бэкенд стартует проверку в фоне и сразу
            // отвечает. Каждый сайт проверяется до 8с — синхронно ждать
            // нельзя, поэтому опрашиваем /status и показываем спиннер.
            const data = await API.post('/api/healthcheck/run', {});
            if (!data || !data.ok) {
                Toast.error((data && data.error) || 'Не удалось запустить проверку');
                setRunBtnLoading(false);
                return;
            }
            const res = data.result || {};
            if (res.busy) {
                Toast.info('Проверка уже идёт…');
            }
            // Сразу показать состояние «идёт проверка».
            await refreshHealthcheck();
            // Поллинг до завершения (checking=false и появился свежий прогон).
            startHealthcheckPoll();
        } catch (err) {
            Toast.error(err.message);
            setRunBtnLoading(false);
        }
    }

    function startHealthcheckPoll() {
        if (healthcheckPollTimer) clearInterval(healthcheckPollTimer);
        let elapsed = 0;
        const startTs = Date.now() / 1000;
        healthcheckPollTimer = setInterval(async () => {
            elapsed += 1.5;
            try {
                const data = await API.get('/api/healthcheck/status');
                const st = (data && data.status) || {};
                // Завершилось: не checking и есть прогон новее старта запроса.
                const done = !st.checking &&
                    st.last_check_at && st.last_check_at >= startTs - 2;
                if (done || elapsed > 45) {
                    clearInterval(healthcheckPollTimer);
                    healthcheckPollTimer = null;
                    setRunBtnLoading(false);
                    renderHealthcheckBody(st);
                    // Тост с итогом.
                    const s = st.last_summary;
                    if (s && s.total) {
                        if (s.global_outage) {
                            Toast.warning('Не открылся ни один сайт — похоже, нет связи или обход не запущен');
                        } else if (s.failed === 0) {
                            Toast.success(`Все ${s.total} сайта доступны`);
                        } else {
                            Toast.warning(`Работает ${s.ok} из ${s.total}`);
                        }
                    }
                    // state мог быть сброшен — освежим таблицу выученных.
                    refreshState();
                } else {
                    renderHealthcheckBody(st);
                }
            } catch (_e) {
                clearInterval(healthcheckPollTimer);
                healthcheckPollTimer = null;
                setRunBtnLoading(false);
            }
        }, 1500);
    }

    function renderHealthcheckBody(st) {
        const body = document.getElementById('healthcheck-body');
        const toggle = document.getElementById('healthcheck-toggle');
        const toggleLabel = document.getElementById('healthcheck-toggle-label');
        if (!body) return;
        if (toggle) toggle.checked = !!st.enabled;
        if (toggleLabel) {
            toggleLabel.textContent = st.running ? 'Включено (работает)'
                : (st.enabled ? 'Включено' : 'Выключено');
        }
        body.innerHTML = renderHealthcheck(st);
        lastHealthStatus = st;
    }

    // ══════════════════ Healthcheck: панель настроек ══════════════════

    let lastHealthStatus = null;
    let knownServicesCache = null;

    async function toggleHealthcheckSettings() {
        const panel = document.getElementById('healthcheck-settings');
        if (!panel) return;
        if (panel.style.display !== 'none') {
            panel.style.display = 'none';
            return;
        }
        // Подгружаем известные сервисы (для чекбоксов) и текущий статус.
        if (!knownServicesCache) {
            try {
                const d = await API.get('/api/diagnostics/services');
                knownServicesCache = (d && (d.services || d.result)) || {};
            } catch (_e) { knownServicesCache = {}; }
        }
        if (!lastHealthStatus) {
            try {
                const d = await API.get('/api/healthcheck/status');
                lastHealthStatus = (d && d.status) || {};
            } catch (_e) { lastHealthStatus = {}; }
        }
        panel.innerHTML = renderHealthcheckSettings(lastHealthStatus, knownServicesCache);
        panel.style.display = '';
    }

    function renderHealthcheckSettings(st, known) {
        const sel = new Set(st.services || []);
        const svcRows = Object.keys(known || {}).map(key => {
            const svc = known[key] || {};
            const checked = sel.has(key) ? 'checked' : '';
            return `<label style="display:inline-flex; align-items:center; gap:5px; margin:2px 10px 2px 0; font-size:13px; cursor:pointer;">
                <input type="checkbox" class="hc-svc" value="${escapeHtml(key)}" ${checked}>
                ${escapeHtml(svc.icon || '')} ${escapeHtml(svc.name || key)}
            </label>`;
        }).join('');
        const custom = (st.custom_domains || []).join('\n');
        return `
            <div style="border:1px solid var(--border, rgba(127,127,127,.2)); border-radius:8px; padding:12px; background:var(--bg-secondary, rgba(127,127,127,.05));">
                <div style="font-weight:600; margin-bottom:8px; font-size:13px;">Настройки авто-починки</div>

                <div style="margin-bottom:10px;">
                    <div style="font-size:12px; color:var(--text-muted); margin-bottom:4px;">Известные сервисы для проверки:</div>
                    <div>${svcRows || '<span class="text-muted">нет</span>'}</div>
                </div>

                <div style="margin-bottom:10px;">
                    <div style="font-size:12px; color:var(--text-muted); margin-bottom:4px;">Свои сайты (по одному в строке: <code>example.com</code> или <code>https://example.com/path</code>):</div>
                    <textarea id="hc-custom" rows="3" style="width:100%; font-family:monospace; font-size:12px; padding:6px;" placeholder="rutracker.org&#10;https://example.com">${escapeHtml(custom)}</textarea>
                </div>

                <div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:10px;">
                    <label style="font-size:13px;">Интервал, мин:
                        <input type="number" id="hc-interval" min="1" max="1440" value="${st.interval_min || 5}" style="width:64px; margin-left:4px;">
                    </label>
                    <label style="font-size:13px;">Сброс после N провалов:
                        <input type="number" id="hc-threshold" min="1" max="20" value="${st.consecutive_failures || 2}" style="width:56px; margin-left:4px;">
                    </label>
                </div>

                <div style="margin-bottom:10px;">
                    <label style="display:flex; align-items:center; gap:6px; font-size:13px; cursor:pointer; margin-bottom:6px;">
                        <input type="checkbox" id="hc-outage-guard" ${st.outage_guard ? 'checked' : ''}>
                        Защита от ложного сброса при «обвале связи»
                    </label>
                    <div style="font-size:12px; color:var(--text-muted); margin-left:24px;">
                        Контрольный сайт (НЕ блокируется — если открывается, значит
                        связь есть и провалы целевых = блокировка, сброс выполняется):
                        <input type="text" id="hc-control" value="${escapeHtml(st.control_domain || '')}" placeholder="ya.ru" style="margin-left:4px; width:140px;">
                        <div style="margin-top:3px;">Пусто = считать обвалом любое падение всех сайтов (старое поведение). Если у вас бывает, что все целевые блокируются разом — оставьте контрольный сайт, и сброс сработает.</div>
                    </div>
                </div>

                <div style="display:flex; gap:8px;">
                    <button class="btn btn-primary btn-sm" onclick="StrategiesPage.saveHealthcheckSettings()">Сохранить</button>
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.toggleHealthcheckSettings()">Отмена</button>
                </div>
            </div>
        `;
    }

    async function saveHealthcheckSettings() {
        const services = Array.from(document.querySelectorAll('.hc-svc'))
            .filter(c => c.checked).map(c => c.value);
        const customRaw = (document.getElementById('hc-custom') || {}).value || '';
        const custom_domains = customRaw.split(/[\n,]+/)
            .map(s => s.trim()).filter(Boolean);
        const interval_min = parseInt((document.getElementById('hc-interval') || {}).value, 10) || 5;
        const consecutive_failures = parseInt((document.getElementById('hc-threshold') || {}).value, 10) || 2;
        const outage_guard = !!(document.getElementById('hc-outage-guard') || {}).checked;
        const control_domain = ((document.getElementById('hc-control') || {}).value || '').trim();

        if (services.length === 0 && custom_domains.length === 0) {
            Toast.error('Выберите хотя бы один сайт для проверки');
            return;
        }
        try {
            const body = { services, custom_domains, interval_min,
                consecutive_failures, outage_guard, control_domain };
            const data = await API.post('/api/healthcheck/config', body);
            if (data && data.ok) {
                Toast.success('Настройки сохранены');
                const panel = document.getElementById('healthcheck-settings');
                if (panel) panel.style.display = 'none';
                if (data.status) renderHealthcheckBody(data.status);
                else refreshHealthcheck();
            } else {
                Toast.error((data && data.error) || 'Не удалось сохранить');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ Autocircular state (z2k-state-persist) ══════════════════

    // Обновить таблицу выученных стратегий. Карточка видна всегда: при пустом
    // state показываем объяснение, как включить автоподбор (применить
    // circular-стратегию), чтобы фича была обнаружимой.
    async function refreshState() {
        const card = document.getElementById('autocircular-state-card');
        const body = document.getElementById('autocircular-state-body');
        if (!card || !body) return;
        try {
            const data = await API.get('/api/strategies/state');
            if (!data || !data.ok) {
                body.innerHTML = emptyStateHtml();
                return;
            }
            const entries = (data.entries || []);
            const summary = data.summary || {};
            if (entries.length === 0) {
                body.innerHTML = emptyStateHtml();
                return;
            }
            body.innerHTML = renderStateTable(entries, summary);
        } catch (_e) {
            body.innerHTML = emptyStateHtml();
        }
    }

    // Пустое состояние: объясняем что это и как включить автоподбор.
    function emptyStateHtml() {
        return `
            <div style="font-size:13px; line-height:1.6; color:var(--text-muted);">
                Пока ничего не выучено. «Автоподбор» — это стратегия типа
                <b>circular</b>: nfqws2 сам перебирает приёмы для каждого сайта
                и запоминает рабочий (память переживает перезагрузку роутера).
                <br><br>
                <b>Как включить автоподбор:</b>
                <ol style="margin:6px 0 10px 18px; padding:0;">
                    <li>Нажмите кнопку ниже — список отфильтруется по авто-стратегиям.</li>
                    <li>Выберите любую «… (circular)» и нажмите «Применить».</li>
                    <li>Открывайте заблокированные сайты — здесь начнут появляться
                        выученные стратегии по доменам.</li>
                </ol>
                <button class="btn btn-primary btn-sm" onclick="StrategiesPage.showCircularStrategies()">
                    <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                    </svg>
                    Показать авто-стратегии
                </button>
                <div style="font-size:11px; margin-top:8px;">
                    Альтернатива — разовый «Подбор стратегий» (вкладка «Подбор»):
                    он один раз протестирует и применит лучшую. circular же
                    подстраивается постоянно и сам.
                </div>
            </div>
        `;
    }

    // Активировать фильтр «Авто (circular)» в списке и прокрутить к нему.
    function showCircularStrategies() {
        if (listUI && listUI.setFilter) {
            listUI.setFilter('circular');
        }
        const host = document.getElementById('strategies-list-host');
        if (host) host.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderStateTable(entries, summary) {
        const fmtTs = (ts) => {
            try { return new Date(ts * 1000).toLocaleString(); }
            catch (_) { return ts; }
        };
        const fmtSummary = () => {
            const byKey = summary.by_key || {};
            const keys = Object.keys(byKey);
            if (keys.length === 0) return '';
            const parts = keys.map(k =>
                `<button class="badge badge-ghost" onclick="StrategiesPage.clearKeyState('${escapeHtml(k)}')" title="Сбросить категорию ${escapeHtml(k)} (${byKey[k]} записей)">${escapeHtml(k)} × ${byKey[k]}</button>`
            );
            return `<div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px;">${parts.join(' ')}</div>`;
        };
        const rows = entries.map(e => `
            <tr>
                <td><code style="font-size:12px;">${escapeHtml(e.host)}</code></td>
                <td><span class="badge badge-ghost">${escapeHtml(e.key)}</span></td>
                <td style="text-align:center;"><strong>#${e.strategy}</strong></td>
                <td class="text-muted" style="font-size:12px;">${escapeHtml(fmtTs(e.ts))}</td>
                <td style="text-align:right;">
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.clearHostState('${escapeHtml(e.host)}')" title="Сбросить выученную стратегию для ${escapeHtml(e.host)} — circular переберёт заново.">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/>
                        </svg>
                    </button>
                </td>
            </tr>
        `).join('');
        return `
            ${fmtSummary()}
            <div style="overflow-x:auto;">
                <table class="data-table" style="width:100%; font-size:13px;">
                    <thead>
                        <tr>
                            <th>Домен</th>
                            <th>Категория</th>
                            <th style="text-align:center;">Стратегия #</th>
                            <th>Закреплено</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    async function clearAllState() {
        if (!confirm('Сбросить все выученные стратегии? circular переберёт заново при следующих соединениях.')) return;
        try {
            const data = await API.delete('/api/strategies/state?reload=1');
            if (data && data.ok) {
                Toast.success(`Сброшено: ${data.removed || 0} записей`);
                refreshState();
            } else {
                Toast.error((data && data.error) || 'Не удалось сбросить state');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function clearHostState(host) {
        if (!host) return;
        if (!confirm(`Сбросить выученную стратегию для домена ${host}?`)) return;
        try {
            const data = await API.delete(
                `/api/strategies/state/host/${encodeURIComponent(host)}?reload=1`);
            if (data && data.ok) {
                Toast.success(`Сброшено: ${host} (${data.removed || 0})`);
                refreshState();
            } else {
                Toast.error((data && data.error) || 'Не удалось сбросить');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function clearKeyState(key) {
        if (!key) return;
        if (!confirm(`Сбросить категорию ${key} (все домены в ней)?`)) return;
        try {
            const data = await API.delete(
                `/api/strategies/state/key/${encodeURIComponent(key)}?reload=1`);
            if (data && data.ok) {
                Toast.success(`Сброшено ${key}: ${data.removed || 0}`);
                refreshState();
            } else {
                Toast.error((data && data.error) || 'Не удалось сбросить');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ Debug-режим nfqws2 ══════════════════

    // Отражает текущее значение nfqws.debug в переключателе активной карточки.
    async function refreshDebugToggle() {
        const el = document.getElementById('nfqws-debug-toggle');
        if (!el) return;
        try {
            const data = await API.get('/api/config');
            const dbg = !!(data && data.config && data.config.nfqws
                           && data.config.nfqws.debug);
            el.checked = dbg;
        } catch (_e) { /* без фатала */ }
    }

    // Открыть страницу «Логи» (журнал) — там виден пер-пакетный вывод nfqws2
    // при включённой отладке. Навигация hash-based (см. app.js).
    function openLogs() {
        window.location.hash = 'logs';
    }

    // Включить/выключить --debug у nfqws2. Сохраняем в конфиг и, если nfqws2
    // запущен, перезапускаем — чтобы отладочный лог появился сразу.
    async function toggleDebug(on) {
        const el = document.getElementById('nfqws-debug-toggle');
        try {
            const res = await API.put('/api/config', { nfqws: { debug: !!on } });
            if (!res || !res.ok) {
                Toast.error((res && res.error) || 'Не удалось сохранить настройку');
                if (el) el.checked = !on;
                return;
            }
            // Применяем сразу: если nfqws2 запущен — перезапуск подхватит --debug.
            let restarted = false;
            try {
                const st = await API.get('/api/status');
                const running = !!(st && (st.nfqws ? st.nfqws.running : st.running));
                if (running) {
                    await API.post('/api/restart', {});
                    restarted = true;
                }
            } catch (_e) { /* статус/перезапуск не критичны для сохранения */ }

            if (on) {
                Toast.success(restarted
                    ? 'Отладка nfqws2 включена, nfqws2 перезапущен — смотрите журнал'
                    : 'Отладка nfqws2 включена (применится при следующем запуске)');
            } else {
                Toast.info(restarted
                    ? 'Отладка nfqws2 выключена, nfqws2 перезапущен'
                    : 'Отладка nfqws2 выключена');
            }
        } catch (err) {
            Toast.error(err.message);
            if (el) el.checked = !on;
        }
    }

    // ══════════════════ Catalog updater ══════════════════

    let catalogPollTimer = null;

    async function refreshCatalogStatus(force = false) {
        try {
            const data = await API.get(
                '/api/catalog/check' + (force ? '?force=1' : '')
            );
            renderCatalogStatus(data);
        } catch (err) {
            const body = document.getElementById('catalog-status-body');
            const card = document.getElementById('catalog-status-card');
            if (body && card) {
                card.style.display = '';
                body.innerHTML = '<span style="color:var(--error);">Не удалось получить статус каталога: '
                    + escapeHtml(err.message) + '</span>';
            }
        }
    }

    function renderCatalogStatus(info) {
        const card = document.getElementById('catalog-status-card');
        const body = document.getElementById('catalog-status-body');
        const btnLabel = document.getElementById('strat-update-btn-label');
        if (!card || !body) return;

        card.style.display = '';

        const files = (info.local && info.local.files) || [];
        const totalStrats = files.reduce(
            (n, f) => n + (f.strategies || 0), 0
        );
        const last = info.local && info.local.last_update;
        const remote = info.remote || {};

        const rows = [];
        rows.push(
            'Файлов: <b>' + files.length + '</b>' +
            ', стратегий: <b>' + totalStrats + '</b>'
        );
        if (last && last.short_sha) {
            rows.push(
                'Установленная версия: <code>' + escapeHtml(last.short_sha) +
                '</code>' +
                (last.updated_at ? ' (обновлено ' +
                    escapeHtml(last.updated_at) + ')' : '')
            );
        } else {
            rows.push('Установленная версия: <i>не отмечалась</i>');
        }
        if (remote.ok && remote.short_sha) {
            rows.push(
                'Последняя версия: <code>' +
                escapeHtml(remote.short_sha) + '</code>' +
                (remote.committed_at ? ' от ' +
                    escapeHtml(remote.committed_at) : '')
            );
        } else if (remote.error) {
            rows.push('<span style="color:var(--error);">Ошибка проверки: '
                + escapeHtml(remote.error) + '</span>');
        }

        if (info.update_available) {
            rows.push(
                '<span style="color:var(--warning);">Доступно обновление.</span>'
            );
            if (btnLabel) btnLabel.textContent = 'Обновить стратегии (новое)';
        } else if (remote.ok) {
            rows.push(
                '<span style="color:var(--success);">Каталог актуален.</span>'
            );
            if (btnLabel) btnLabel.textContent = 'Обновить стратегии';
        }

        body.innerHTML = rows.join('<br>');
    }

    async function updateCatalog() {
        const btn = document.getElementById('strat-update-btn');
        if (btn) btn.disabled = true;
        Toast.info('Обновление каталога стратегий...');

        try {
            const resp = await API.post('/api/catalog/update', {});
            if (resp.in_progress) {
                startCatalogPolling();
                return;
            }
            if (resp.ok) {
                Toast.success(resp.message || 'Каталог обновлён');
                await refreshCatalogStatus(true);
                await fetchStrategies();
            } else {
                Toast.error(resp.message || 'Ошибка обновления');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function startCatalogPolling() {
        if (catalogPollTimer) return;
        const btn = document.getElementById('strat-update-btn');
        catalogPollTimer = setInterval(async () => {
            try {
                const p = await API.get('/api/catalog/progress');
                if (!p.in_progress) {
                    clearInterval(catalogPollTimer);
                    catalogPollTimer = null;
                    if (btn) btn.disabled = false;
                    Toast.success('Обновление каталога завершено');
                    await refreshCatalogStatus(true);
                    await fetchStrategies();
                }
            } catch (err) {
                clearInterval(catalogPollTimer);
                catalogPollTimer = null;
                if (btn) btn.disabled = false;
                Toast.error('Ошибка опроса прогресса: ' + err.message);
            }
        }, 1500);
    }

    // ══════════════════ Data ══════════════════

    let listUI = null;

    async function fetchStrategies() {
        try {
            const data = await API.get('/api/strategies');
            strategies = data.strategies || [];

            // Определяем активную
            const active = strategies.find(s => s.is_active);
            currentId = active ? active.id : null;
            favorites = strategies.filter(s => s.is_favorite).map(s => s.id);

            // Чистим выделение от исчезнувших стратегий (напр. после объединения).
            Array.from(selectedIds).forEach(id => {
                if (!strategies.find(s => s.id === id)) selectedIds.delete(id);
            });

            renderActiveCard(active);
            renderList(strategies);
            renderBulkBar();
        } catch (err) {
            const host = document.getElementById('strategies-list-host');
            if (host) {
                host.innerHTML =
                    '<div class="card" style="text-align:center; padding:24px; color:var(--error);">Ошибка загрузки: ' + escapeHtml(err.message) + '</div>';
            }
        }
    }

    // ══════════════════ Render List (через ListUI) ══════════════════

    function setFilter(_filter) {
        // Совместимость со старым API — фильтры теперь внутри ListUI.
        if (listUI) listUI.refresh();
    }

    function renderActiveCard(active) {
        const el = document.getElementById('active-strategy-info');
        if (!el) return;

        if (active) {
            el.innerHTML = `
                <span class="status-dot running"></span>
                <div>
                    <div style="font-weight:500; color:var(--text-heading);">${escapeHtml(active.name)}</div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${escapeHtml(active.description || '')}</div>
                </div>
                <div style="margin-left:auto; display:flex; gap:6px;">
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.showPreview('${active.id}')" title="Превью команды">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                    </button>
                </div>
            `;
        } else {
            el.innerHTML = `
                <span class="status-dot stopped"></span>
                <span class="text-muted">Не выбрана</span>
                <span style="margin-left:auto; font-size:12px; color:var(--text-muted);">Выберите стратегию из списка ниже</span>
            `;
        }
    }

    function renderList(list) {
        const host = document.getElementById('strategies-list-host');
        if (!host) return;

        // Если ListUI уже создан — просто обновляем данные.
        if (listUI) { listUI.setItems(list); return; }

        const container = document.createElement('div');
        container.id = 'strategies-list';
        host.innerHTML = '';
        host.appendChild(container);

        listUI = ListUI.create({
            container,
            items: list,
            searchPlaceholder: 'Поиск по имени, автору, описанию, args...',
            searchFields: s => [
                s.name, s.description, s.author, s.label, s.id,
                (s.profiles || []).map(p => p.args || '').join(' '),
            ],
            filters: [
                { id: 'all', label: 'Все', test: () => true, default: true },
                { id: 'circular', label: '⟳ Авто (circular)',
                  test: s => /(?:^|[^a-z])circular/i.test(
                      (s.profiles || []).map(p => p.args || '').join(' ')) },
                { id: 'favorites', label: '★ Избранное', test: s => s.is_favorite },
                { id: 'recommended', label: 'Рекомендуемые', test: s => s.label === 'recommended' },
                { id: 'builtin', label: 'Встроенные', test: s => s.is_builtin },
                { id: 'user', label: 'Пользовательские', test: s => !s.is_builtin },
            ],
            groupBy: s => (s.protocol || 'other').toLowerCase(),
            groupLabel: g => ({
                tcp: 'TCP', udp: 'UDP / QUIC', http: 'HTTP', tls: 'TLS', other: 'Прочее',
            }[g] || String(g).toUpperCase()),
            renderItem: renderStrategyCard,
            pageSize: 80,
            storageKey: 'strategies-list',
            renderEmpty: (q, f) => `<div class="list-ui-empty">${
                q ? 'По запросу «' + escapeHtml(q) + '» ничего не найдено' :
                f === 'favorites' ? 'Нет избранных стратегий. Нажмите ★ на любой карточке.' :
                f === 'user' ? 'Нет пользовательских стратегий. Создайте первую кнопкой выше.' :
                'Нет стратегий'
            }</div>`,
            countLabel: (v, t) => v + ' из ' + t + ' стратегий',
        });
    }

    /**
     * Карточка стратегии. По умолчанию компактная (имя/бейджи/действия);
     * подробности (профили, args) раскрываются кнопкой «Подробнее» —
     * ListUI обрабатывает клик по [data-list-ui-toggle].
     */
    function renderStrategyCard(s) {
        const isActive = s.id === currentId;
        const isFav = s.is_favorite;
        const isBuiltin = s.is_builtin;
        const isSelected = selectedIds.has(s.id);

        const labelTag = s.label
            ? `<span class="label ${escapeAttr(s.label)}">${escapeHtml(s.label)}</span>` : '';
        const authorTag = s.author
            ? `<span title="Автор">${escapeHtml(s.author)}</span>` : '';
        const metaInline = (labelTag || authorTag)
            ? `<span class="strategy-card-meta">${labelTag}${authorTag}</span>` : '';

        const profileBadges = (s.profiles || []).map(p => {
            const enabled = p.enabled !== false;
            let color = 'var(--text-muted)';
            const label = p.name || p.id;
            const ll = label.toLowerCase();
            if (ll.includes('http') && !ll.includes('https') && !ll.includes('tls')) color = 'var(--warning)';
            if (ll.includes('tls')) color = 'var(--success)';
            if (ll.includes('quic') || ll.includes('udp')) color = 'var(--info)';
            return `<span class="profile-badge${enabled ? '' : ' disabled'}" style="--badge-color:${color};">${escapeHtml(label)}</span>`;
        }).join('');

        const argsBlocks = (s.profiles || []).filter(p => p.enabled !== false).map(p => {
            const args = p.args || '';
            if (!args) return '';
            return '<div class="strategy-args-preview">' + NfqwsSyntax.highlight(args) + '</div>';
        }).join('');

        return `
            <div class="strategy-card compact${isActive ? ' active' : ''}${isSelected ? ' selected' : ''}" data-id="${s.id}" data-list-ui-card>
                <div class="strategy-card-header">
                    <label class="strategy-select-label" title="Выделить для объединения с другими стратегиями" onclick="event.stopPropagation();">
                        <input type="checkbox" class="strategy-select"${isSelected ? ' checked' : ''} onclick="StrategiesPage.toggleSelect(event, '${escapeAttr(s.id)}')">
                    </label>
                    <div class="strategy-card-info">
                        <div class="strategy-card-name">
                            ${isActive ? '<span class="status-dot running" style="width:8px;height:8px;"></span>' : ''}
                            ${escapeHtml(s.name)}
                            ${isBuiltin ? '<span class="badge badge-muted">builtin</span>' : '<span class="badge badge-accent">user</span>'}
                            ${metaInline}
                        </div>
                        ${s.description ? `<div class="strategy-card-desc">${escapeHtml(s.description)}</div>` : ''}
                    </div>
                    <button class="btn-icon-only fav-btn${isFav ? ' active' : ''}" onclick="StrategiesPage.toggleFavorite('${s.id}')" title="${isFav ? 'Убрать из избранного' : 'В избранное'}">
                        <svg viewBox="0 0 24 24" fill="${isFav ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                        </svg>
                    </button>
                </div>
                <div class="strategy-card-profiles">${profileBadges}</div>
                <div class="strategy-card-args-wrap">${argsBlocks}</div>
                <div class="strategy-card-actions">
                    <button class="btn btn-primary btn-sm" onclick="StrategiesPage.applyStrategy('${s.id}')"${isActive ? ' disabled' : ''}>
                        ${isActive ? '✓ Активна' : 'Применить'}
                    </button>
                    <button class="strategy-card-toggle" data-list-ui-toggle title="Развернуть/свернуть подробности">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
                            <polyline points="6 9 12 15 18 9"/>
                        </svg>
                        Подробнее
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.showPreview('${s.id}')" title="Превью команды">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                        </svg>
                        Превью
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.copyStrategyToClipboard('${s.id}')" title="Скопировать стратегию со всеми профилями (через --new) в буфер обмена">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                        </svg>
                        В буфер
                    </button>
                    ${!isBuiltin ? `
                        <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.openEdit('${s.id}')" title="Редактировать">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.deleteStrategy('${s.id}')" title="Удалить" style="color:var(--error);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    ` : `
                        <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.duplicateStrategy('${s.id}')" title="Копировать как пользовательскую">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                            Копировать
                        </button>
                    `}
                </div>
            </div>
        `;
    }

    function escapeAttr(text) {
        return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ══════════════════ Actions ══════════════════

    async function applyStrategy(sid) {
        const s = strategies.find(x => x.id === sid);
        if (!s) return;

        if (!confirm('Применить стратегию "' + s.name + '"?\n\nnfqws2 будет перезапущен.')) return;

        try {
            const result = await API.post('/api/strategies/' + sid + '/apply', {});
            if (result.ok) {
                Toast.success('Стратегия применена: ' + s.name);
                fetchStrategies();
            } else {
                Toast.error(result.error || 'Ошибка применения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function toggleFavorite(sid) {
        try {
            const result = await API.post('/api/strategies/' + sid + '/favorite', {});
            if (result.ok) {
                // Обновляем локально
                const s = strategies.find(x => x.id === sid);
                if (s) s.is_favorite = result.is_favorite;
                favorites = strategies.filter(s => s.is_favorite).map(s => s.id);
                renderList(strategies);
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function deleteStrategy(sid) {
        const s = strategies.find(x => x.id === sid);
        if (!s) return;

        if (!confirm('Удалить стратегию "' + s.name + '"?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.delete('/api/strategies/' + sid);
            if (result.ok) {
                Toast.success('Стратегия удалена');
                fetchStrategies();
            } else {
                Toast.error(result.error || 'Ошибка удаления');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function duplicateStrategy(sid) {
        const s = strategies.find(x => x.id === sid);
        if (!s) return;
        openEditor({
            id: s.id + '_copy',
            name: s.name + ' (копия)',
            description: s.description || '',
            type: s.type || 'combined',
            profiles: JSON.parse(JSON.stringify(s.profiles || [])),
        }, 'create');
    }

    // ══════════════════ Preview ══════════════════

    async function showPreview(sid) {
        const modal = document.getElementById('preview-modal');
        const cmdEl = document.getElementById('preview-command');
        if (!modal || !cmdEl) return;

        modal.style.display = 'flex';
        cmdEl.textContent = 'Загрузка...';
        modal._sid = sid;

        // Сбрасываем блок результата валидации от прошлого открытия.
        const valEl = document.getElementById('preview-validation');
        if (valEl) { valEl.style.display = 'none'; valEl.innerHTML = ''; }

        try {
            const result = await API.post('/api/strategies/preview', { strategy_id: sid });
            if (result.ok) {
                cmdEl.innerHTML = NfqwsSyntax.highlightCommand(result.command);
                cmdEl._rawText = result.command;
            } else {
                cmdEl.textContent = 'Ошибка: ' + (result.error || '?');
                cmdEl._rawText = cmdEl.textContent;
            }
        } catch (err) {
            cmdEl.textContent = 'Ошибка: ' + err.message;
            cmdEl._rawText = cmdEl.textContent;
        }
    }

    async function validatePreview() {
        const modal = document.getElementById('preview-modal');
        const valEl = document.getElementById('preview-validation');
        const btn = document.getElementById('preview-validate-btn');
        if (!modal || !valEl || !modal._sid) return;

        const sid = modal._sid;
        valEl.style.display = 'block';
        valEl.innerHTML = '<div class="alert alert-info" style="margin:0;">Проверка через nfqws2 --intercept=0…</div>';
        if (btn) btn.disabled = true;

        try {
            const res = await API.post('/api/strategies/' + encodeURIComponent(sid) + '/validate', {});
            const v = res && res.validation;
            if (!res || !res.ok || !v) {
                valEl.innerHTML = '<div class="alert alert-danger" style="margin:0;">Ошибка: ' +
                    ((res && res.error) || '?') + '</div>';
                return;
            }
            if (!v.available) {
                valEl.innerHTML = '<div class="alert alert-warning" style="margin:0;">' +
                    'Валидация недоступна: бинарник nfqws2 не найден на этом устройстве ' +
                    '(на роутере проверка работает).</div>';
                return;
            }
            const out = (v.output || '').trim();
            const outBlock = out
                ? '<pre style="margin:8px 0 0; max-height:200px; overflow:auto; white-space:pre-wrap; word-break:break-all; font-size:11px; opacity:.85;">' +
                  escapeHtml(out) + '</pre>'
                : '';
            if (v.ok) {
                valEl.innerHTML = '<div class="alert alert-success" style="margin:0;">' +
                    '✓ Стратегия валидна — nfqws2 принял параметры и lua-init (код 0). ' +
                    'NFQUEUE не поднимался, трафик не затрагивался.' + outBlock + '</div>';
            } else {
                valEl.innerHTML = '<div class="alert alert-danger" style="margin:0;">' +
                    '✗ Стратегия не прошла проверку (код ' + (v.returncode != null ? v.returncode : '?') +
                    '). Частые причины: ошибка синтаксиса/загрузки lua-скрипта, ' +
                    'отсутствующий файл --blob/--lua-init/--hostlist, кривой параметр CLI.' + outBlock + '</div>';
            }
        } catch (err) {
            valEl.innerHTML = '<div class="alert alert-danger" style="margin:0;">Ошибка: ' + err.message + '</div>';
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    function closePreview() {
        const modal = document.getElementById('preview-modal');
        if (modal) modal.style.display = 'none';
    }

    function copyPreview() {
        const cmdEl = document.getElementById('preview-command');
        if (!cmdEl) return;
        const text = cmdEl._rawText || cmdEl.textContent;
        navigator.clipboard.writeText(text).then(() => {
            Toast.success('Команда скопирована');
        }).catch(() => {
            // Fallback
            const range = document.createRange();
            range.selectNode(cmdEl);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            window.getSelection().removeAllRanges();
            Toast.success('Команда скопирована');
        });
    }

    // ══════════════════ Editor Modal ══════════════════

    function openCreate() {
        openEditor({
            id: '',
            name: '',
            description: '',
            type: 'combined',
            profiles: [
                { id: 'tls443', name: 'TLS (порт 443)', enabled: true, args: '--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls' },
            ],
        }, 'create');
    }

    function openEdit(sid) {
        const s = strategies.find(x => x.id === sid);
        if (!s) return;
        openEditor(JSON.parse(JSON.stringify(s)), 'edit');
    }

    let editorData = null;
    let editorMode = 'create';

    function openEditor(data, mode) {
        editorData = data;
        editorMode = mode;
        editorActive = { index: 0, cursor: 0 };

        const modal = document.getElementById('strategy-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        if (!modal || !body) return;

        title.textContent = mode === 'create' ? 'Создать стратегию' : 'Редактировать стратегию';
        modal.style.display = 'flex';

        // Грузим список hostlist-файлов и перерисовываем форму, чтобы дропдаун был актуален
        renderEditorForm(body);
        // Делаем окно растягиваемым во все стороны (ширина по умолчанию 2× — §5).
        // Вызываем ПОСЛЕ renderEditorForm, чтобы измерить высоту формы.
        enableModalResize();
        attachAutocompleteToProfiles();
        loadHostlistFiles().then(() => {
            // Перерисовываем только список профилей, не трогая остальные поля
            const el = document.getElementById('profiles-editor');
            if (el && editorData && editorData.profiles) {
                // Сохраняем текущие значения args/name из DOM (могли быть отредактированы)
                collectEditorData();
                el.innerHTML = editorData.profiles.map((p, i) => renderProfileEditor(p, i)).join('');
                attachAutocompleteToProfiles();
            }
        });
    }

    function renderEditorForm(container) {
        const d = editorData;
        const isCreate = editorMode === 'create';

        container.innerHTML = `
          <div class="strat-editor-layout">
            <div class="strat-editor-main">
              <div class="form-group">
                <label class="form-label">ID стратегии</label>
                <input type="text" id="edit-id" class="form-input" value="${escapeHtml(d.id)}" placeholder="my_strategy" ${!isCreate ? 'readonly style="opacity:0.6;"' : ''}>
                <div class="form-hint">Латиница, цифры, дефис, подчёркивание</div>
              </div>
              <div class="form-group">
                <label class="form-label">Название</label>
                <input type="text" id="edit-name" class="form-input" value="${escapeHtml(d.name)}" placeholder="Моя стратегия">
              </div>
              <div class="form-group">
                <label class="form-label">Описание</label>
                <input type="text" id="edit-desc" class="form-input" value="${escapeHtml(d.description || '')}" placeholder="Краткое описание стратегии">
              </div>

              <div class="form-group">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <label class="form-label" style="margin-bottom:0;">Профили</label>
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.addProfile()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                        </svg>
                        Добавить
                    </button>
                </div>
                <div id="profiles-editor">
                    ${d.profiles.map((p, i) => renderProfileEditor(p, i)).join('')}
                </div>
              </div>

              <div class="form-group" style="margin-top:16px;">
                <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.editorPreview()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                    </svg>
                    Превью команды
                </button>
                <div id="editor-preview-output" class="log-viewer nfq-resizable" style="height:120px; margin-top:8px; display:none; white-space:pre-wrap; word-break:break-all; font-size:11px; padding:12px;"></div>
              </div>

              <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:20px; padding-top:16px; border-top:1px solid var(--border);">
                <button class="btn btn-ghost" onclick="StrategiesPage.closeModal()">Отмена</button>
                <button class="btn btn-primary" onclick="StrategiesPage.saveEditor()">
                    ${isCreate ? 'Создать' : 'Сохранить'}
                </button>
              </div>
            </div>

            <!-- Боковая панель «как в IDE»: скелет стратегии + подсказки по коду -->
            <aside class="strat-editor-side" id="editor-sidepanel"></aside>
          </div>
        `;
    }

    function renderProfileEditor(profile, index) {
        const enabled = profile.enabled !== false;
        const hostlistOptions = hostlistFiles.map(f => {
            const badge = f.is_builtin ? '' : ' [user]';
            return `<option value="${escapeHtml(f.path)}">${escapeHtml(f.filename || f.name)}${badge}</option>`;
        }).join('');
        return `
            <div class="profile-editor-item" data-index="${index}">
                <div class="profile-editor-header">
                    <label class="toggle-label" style="flex:1; display:flex; align-items:center; gap:8px;">
                        <input type="checkbox" class="profile-toggle" ${enabled ? 'checked' : ''} onchange="StrategiesPage.toggleProfile(${index}, this.checked)">
                        <input type="text" class="form-input form-input-sm" value="${escapeHtml(profile.name || profile.id)}" placeholder="Имя профиля" onchange="StrategiesPage.updateProfileName(${index}, this.value)" style="flex:1; max-width:260px;">
                    </label>
                    <div style="display:flex; align-items:center; gap:6px;">
                        <select class="form-input form-input-sm profile-filter-picker" data-index="${index}"
                                onchange="StrategiesPage.insertFilter(${index}, this)"
                                title="Вставить --filter-* + --payload в начало профиля (порт/протокол)"
                                style="max-width:150px;">
                            <option value="">+ фильтр…</option>
                            <option value="tls443">TCP 443 · TLS</option>
                            <option value="http80">TCP 80 · HTTP</option>
                            <option value="quic443">UDP 443 · QUIC</option>
                        </select>
                        <select class="form-input form-input-sm profile-hostlist-picker" data-index="${index}"
                                onchange="StrategiesPage.insertHostlist(${index}, this)"
                                title="Вставить --hostlist=<файл> в аргументы профиля"
                                style="max-width:200px;">
                            <option value="">+ hostlist…</option>
                            ${hostlistOptions}
                        </select>
                        <button class="btn-icon-only" onclick="StrategiesPage.removeProfile(${index})" title="Удалить профиль" style="color:var(--error); opacity:0.7;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="profile-args-wrap nfq-editor" data-index="${index}">
                    <pre class="nfq-editor-pre" aria-hidden="true"></pre>
                    <textarea class="form-textarea profile-args nfq-editor-ta" rows="3" wrap="off" spellcheck="false" placeholder="--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls" onchange="StrategiesPage.updateProfileArgs(${index}, this.value)">${escapeHtml(profile.args || '')}</textarea>
                    <span class="profile-args-hint">Ctrl+Space</span>
                </div>
                <div class="profile-hint-msg" id="profile-hint-${index}">${renderProfileHint(profile.args || '')}</div>
            </div>
        `;
    }

    // Контекстная подсказка по args профиля (SKILL §2/§4): предупреждаем о
    // «голом приёме» без фильтра и поясняем, что порт берётся из firewall, а
    // фильтр выводится автоматически (см. превью).
    function profileHint(args) {
        const a = String(args || '');
        if (!/--lua-desync/.test(a)) return null;
        const hasFilter = /--filter-(?:tcp|udp|l7)\b/.test(a);
        if (!hasFilter) {
            const pm = a.match(/--payload=([a-z_]+)/i);
            const known = pm && /^(tls_client_hello|http_req|http_reply|quic_initial)$/.test(pm[1]);
            const text = known
                ? 'Приём без --filter-*: будет автоматически ограничен по --payload (см. «Превью команды»). '
                    + 'Порты задаёт firewall (nfqws.ports_tcp/udp).'
                : 'Приём без --filter-* и без однозначного --payload: десинк применится ко всему '
                    + 'трафику очереди (порты firewall). Ограничьте порт/протокол — «+ фильтр…».';
            return { level: 'warn', text };
        }
        const m = a.match(/(?:blob|pattern|seqovl_pattern)=([A-Za-z_][A-Za-z0-9_]*)/g);
        if (m && m.some(x => !/=fake_default_(?:tls|http|quic)$/.test(x))) {
            return {
                level: 'info',
                text: 'Именованный паттерн → подключится init_vars.lua.',
            };
        }
        return null;
    }

    // Критичный кусок цели задан? (домен/ip/hostlist/ipset). Если в профиле
    // есть приём (--lua-desync), но НЕ задано ничего из перечисленного — десинк
    // применится ко всему трафику очереди. Используется для подсказки при
    // сохранении (SKILL §1: сначала подсказать, авто-добавить только если
    // пользователь проигнорировал).
    function profileTargetMissing(args) {
        const a = String(args || '');
        if (!/--lua-desync/.test(a)) return false; // не приём — пропускаем
        // include-формы, реально ограничивающие цель (exclude не в счёт):
        const hasTarget = /--hostlist=|--hostlist-domains=|--hostlist-auto=|--ipset=|--ipset-ip=/.test(a);
        return !hasTarget;
    }

    // Превью args профиля с выделенным КРАСНЫМ недостающим куском цели.
    // Вставляем пример --hostlist=<домены> в правильное место (после
    // фильтров, перед --payload/--lua-desync), чтобы пользователь видел,
    // куда дописать забытый кусок прямо в этом же окне.
    function highlightMissingTarget(args) {
        const a = String(args || '');
        const redSpan = '<span class="hint-missing">--hostlist=&lt;домены&gt;</span>';
        const m = a.match(/--payload=|--lua-desync=/);
        if (m) {
            const idx = m.index;
            const left = a.slice(0, idx);
            const sep = (left && !/\s$/.test(left)) ? ' ' : '';
            return escapeHtml(left) + sep + redSpan + ' ' + escapeHtml(a.slice(idx));
        }
        const sep = (a && !/\s$/.test(a)) ? ' ' : '';
        return escapeHtml(a) + sep + redSpan;
    }

    function renderProfileHint(args) {
        const blocks = [];

        // Диагностика синтаксиса (линтер nfqws2): ошибки и предупреждения
        // прямо под редактором. Структурные (весь трафик/порядок) показываем
        // в боковой панели, чтобы не дублировать действенное превью ниже.
        let analysis = null;
        try { analysis = Nfqws2Lint.analyze(String(args || '')); } catch (_e) { analysis = null; }
        if (analysis) {
            const errs = analysis.diagnostics.filter(d => d.severity === 'error');
            const warns = analysis.diagnostics.filter(d => d.severity === 'warn' && !d.structural);
            errs.slice(0, 5).forEach(d => {
                blocks.push('<div class="profile-hint-err">✕ ' + escapeHtml(d.message) + '</div>');
            });
            warns.slice(0, 3).forEach(d => {
                blocks.push('<div class="profile-hint-warn">⚠ ' + escapeHtml(d.message) + '</div>');
            });
            const more = (errs.length - 5) + (warns.length - 3);
            if (errs.length > 5 || warns.length > 3) {
                blocks.push('<div class="profile-hint-info">…ещё '
                    + Math.max(0, more) + ' — см. «Проверка синтаксиса» в панели справа.</div>');
            }
        }

        // Забыт критичный кусок цели → встроенное превью с красным выделением.
        if (profileTargetMissing(args)) {
            blocks.push(
                '<div class="profile-hint-warn">⚠ Забыт критичный кусок цели '
                + '(домен / ip / hostlist / ipset). Без него десинк затронет '
                + '<b>весь</b> трафик очереди.</div>'
                + '<div class="profile-hint-preview">'
                + '<span class="profile-hint-preview-label">Превью:</span> '
                + '<code>' + highlightMissingTarget(args) + '</code></div>'
                + '<div class="profile-hint-info">Допишите выделенный кусок '
                + '(<code>--hostlist=</code>/<code>--hostlist-domains=</code>/'
                + '<code>--ipset-ip=</code> — кнопка «+ hostlist…») или сохраните '
                + 'как есть: ограничение добавится автоматически (при включённом '
                + '«Едином слое»).</div>'
            );
        }

        const h = profileHint(args);
        if (h && h.level === 'info') {
            blocks.push(`<span class="profile-hint-info">ℹ ${escapeHtml(h.text)}</span>`);
        }
        return blocks.join('');
    }

    function updateProfileHintEl(index) {
        const el = document.getElementById('profile-hint-' + index);
        if (!el || !editorData || !editorData.profiles[index]) return;
        el.innerHTML = renderProfileHint(editorData.profiles[index].args || '');
    }

    function insertFilter(index, selectEl) {
        if (!selectEl) return;
        const key = selectEl.value;
        selectEl.value = '';
        const snippet = FILTER_PRESETS[key];
        if (!snippet) return;

        const item = document.querySelector('.profile-editor-item[data-index="' + index + '"]');
        if (!item) return;
        const textarea = item.querySelector('.profile-args');
        if (!textarea) return;

        // Фильтр ведёт профиль — вставляем в начало.
        const val = textarea.value.trim();
        textarea.value = val ? (snippet + ' ' + val) : snippet;
        textarea.focus();
        textarea.setSelectionRange(snippet.length, snippet.length);
        updateProfileArgs(index, textarea.value);
    }

    function insertHostlist(index, selectEl) {
        if (!selectEl) return;
        const path = selectEl.value;
        // Сбрасываем выбор независимо от результата
        selectEl.value = '';
        if (!path) return;

        const item = document.querySelector('.profile-editor-item[data-index="' + index + '"]');
        if (!item) return;
        const textarea = item.querySelector('.profile-args');
        if (!textarea) return;

        const snippet = '--hostlist=' + path;

        // Вставка в позицию курсора; если курсор в середине строки и слева не пробел — добавляем пробел
        const start = textarea.selectionStart || 0;
        const end = textarea.selectionEnd || 0;
        const val = textarea.value;
        const before = val.slice(0, start);
        const after = val.slice(end);
        const leftSep = (before.length && !/\s$/.test(before)) ? ' ' : '';
        const rightSep = (after.length && !/^\s/.test(after)) ? ' ' : '';
        const insertion = leftSep + snippet + rightSep;

        textarea.value = before + insertion + after;
        const newPos = before.length + insertion.length;
        textarea.focus();
        textarea.setSelectionRange(newPos, newPos);

        updateProfileArgs(index, textarea.value);
    }

    async function loadHostlistFiles() {
        try {
            const result = await API.get('/api/hostlists');
            if (result && result.ok) {
                hostlistFiles = result.files || [];
            }
        } catch (err) {
            hostlistFiles = [];
        }
    }

    function addProfile() {
        if (!editorData) return;
        editorData.profiles.push({
            id: 'profile_' + Date.now(),
            name: 'Новый профиль',
            enabled: true,
            args: '',
        });
        const el = document.getElementById('profiles-editor');
        if (el) el.innerHTML = editorData.profiles.map((p, i) => renderProfileEditor(p, i)).join('');
        attachAutocompleteToProfiles();
    }

    function removeProfile(index) {
        if (!editorData) return;
        if (editorData.profiles.length <= 1) {
            Toast.warning('Нужен хотя бы один профиль');
            return;
        }
        editorData.profiles.splice(index, 1);
        const el = document.getElementById('profiles-editor');
        if (el) el.innerHTML = editorData.profiles.map((p, i) => renderProfileEditor(p, i)).join('');
        attachAutocompleteToProfiles();
    }

    function toggleProfile(index, enabled) {
        if (!editorData || !editorData.profiles[index]) return;
        editorData.profiles[index].enabled = enabled;
    }

    function updateProfileName(index, name) {
        if (!editorData || !editorData.profiles[index]) return;
        editorData.profiles[index].name = name;
    }

    function updateProfileArgs(index, args) {
        if (!editorData || !editorData.profiles[index]) return;
        editorData.profiles[index].args = args;
        const item = document.querySelector('.profile-editor-item[data-index="' + index + '"]');
        if (item) syncOverlay(item);          // подсветка + кэш анализа
        updateProfileHintEl(index);            // инлайн-диагностика под редактором
        if (editorActive.index === index) renderSidePanel();  // панель справа
    }

    // Открыть редактор СОЗДАНИЯ, предзаполненный приёмом из blockcheck2.
    // payload: { name, description, args }. Реконструкция дословная: фильтр +
    // payload (из типа теста) + lua-desync (как нашёл blockcheck2).
    function prefillCreate(payload) {
        pendingPrefill = payload || null;
        if (window.location.hash.slice(1) === 'strategies') {
            // Уже на странице — открываем сразу (render не вызовется повторно).
            consumePendingPrefill();
        } else {
            window.location.hash = 'strategies';
        }
    }

    function consumePendingPrefill() {
        if (!pendingPrefill) return;
        const p = pendingPrefill;
        pendingPrefill = null;
        openEditor({
            id: '',
            name: p.name || '',
            description: p.description || '',
            type: 'combined',
            profiles: [
                { id: 'bc2', name: p.name || 'blockcheck2', enabled: true,
                  args: p.args || '' },
            ],
        }, 'create');
    }

    async function editorPreview() {
        collectEditorData();
        const output = document.getElementById('editor-preview-output');
        if (!output) return;
        output.style.display = 'block';
        output.textContent = 'Загрузка...';

        try {
            const result = await API.post('/api/strategies/preview', { strategy_data: editorData });
            if (result.ok) {
                output.innerHTML = NfqwsSyntax.highlightCommand(result.command);
            } else {
                output.textContent = 'Ошибка: ' + (result.error || '?');
            }
        } catch (err) {
            output.textContent = 'Ошибка: ' + err.message;
        }
    }

    function collectEditorData() {
        if (!editorData) return;
        const id = document.getElementById('edit-id');
        const name = document.getElementById('edit-name');
        const desc = document.getElementById('edit-desc');
        if (id) editorData.id = id.value.trim();
        if (name) editorData.name = name.value.trim();
        if (desc) editorData.description = desc.value.trim();

        // Profiles — args might have been changed via textarea
        const textareas = document.querySelectorAll('.profile-args');
        textareas.forEach((ta, i) => {
            if (editorData.profiles[i]) {
                editorData.profiles[i].args = ta.value;
            }
        });
    }

    async function saveEditor() {
        collectEditorData();

        if (!editorData.id) {
            Toast.error('Укажите ID стратегии');
            return;
        }
        if (!editorData.name) {
            Toast.error('Укажите название стратегии');
            return;
        }
        if (!editorData.profiles.length) {
            Toast.error('Добавьте хотя бы один профиль');
            return;
        }

        // Генерируем id для профилей если нет
        editorData.profiles.forEach((p, i) => {
            if (!p.id) p.id = 'profile_' + i;
        });

        try {
            let result;
            if (editorMode === 'create') {
                result = await API.post('/api/strategies', editorData);
            } else {
                result = await API.put('/api/strategies/' + editorData.id, editorData);
            }

            if (result.ok) {
                Toast.success(editorMode === 'create' ? 'Стратегия создана' : 'Стратегия обновлена');
                // Забираем отложенный коллбэк ДО closeModal (он его сбрасывает).
                const onSaved = editorOnSaved;
                closeModal();
                fetchStrategies();
                if (typeof onSaved === 'function') onSaved();
            } else {
                Toast.error(result.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // Полная настройка IDE-редакторов профилей: автодополнение + overlay-подсветка
    // с диагностикой + боковая панель (скелет/подсказки). Имя сохранено —
    // вызывается из openEditor/addProfile/removeProfile/prefill.
    function attachAutocompleteToProfiles() {
        NfqwsAutocomplete.detachAll();
        NfqwsAutocomplete.loadFiles();
        if (editorData && editorData.profiles) {
            if (editorActive.index >= editorData.profiles.length) editorActive.index = 0;
        }
        setTimeout(() => {
            document.querySelectorAll('.profile-editor-item').forEach(item => {
                const ta = item.querySelector('.profile-args');
                if (!ta) return;
                NfqwsAutocomplete.attach(ta);
                mountOverlayEditor(item, ta);
                syncOverlay(item);
            });
            renderSidePanel();
        }, 0);
    }

    // ══════════════════ IDE: overlay-подсветка + диагностика ══════════════════

    // Навесить на textarea профиля синхронизацию подсветки и обновление панели.
    function mountOverlayEditor(item, ta) {
        if (ta._nfqMounted) return;
        ta._nfqMounted = true;
        const idx = parseInt(item.dataset.index, 10) || 0;

        // Изменение текста: пересобрать данные, подсветку, инлайн-диагностику, панель.
        ta.addEventListener('input', () => {
            editorActive = { index: idx, cursor: ta.selectionStart || 0 };
            updateProfileArgs(idx, ta.value);
        });
        // Перемещение курсора (стрелки/клик/выделение/фокус) — обновить подсказку панели.
        const onCursor = () => {
            editorActive = { index: idx, cursor: ta.selectionStart || 0 };
            renderSidePanel();
        };
        ta.addEventListener('keyup', onCursor);
        ta.addEventListener('click', onCursor);
        ta.addEventListener('focus', onCursor);
        ta.addEventListener('select', onCursor);
        // Прокрутка textarea — синхронно прокрутить слой подсветки.
        ta.addEventListener('scroll', () => {
            const pre = item.querySelector('.nfq-editor-pre');
            if (pre) { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; }
        });
    }

    // Перерисовать слой подсветки (с разметкой ошибок) под текущий текст профиля.
    // Анализ кэшируется на элементе для боковой панели/инлайна (один lint на изменение).
    function syncOverlay(item) {
        const ta = item.querySelector('.profile-args');
        const pre = item.querySelector('.nfq-editor-pre');
        if (!ta || !pre) return;
        const text = ta.value;
        let analysis = null;
        try { analysis = Nfqws2Lint.analyze(text); } catch (_e) { analysis = null; }
        item._analysis = analysis;
        const diags = analysis ? analysis.diagnostics : [];
        let html = NfqwsSyntax.highlightWithDiagnostics(text, diags);
        // хвостовой перенос строки — добавить «якорь», чтобы высота слоя совпала
        if (text.endsWith('\n')) html += '​';
        pre.innerHTML = html || '​';
        pre.scrollTop = ta.scrollTop;
        pre.scrollLeft = ta.scrollLeft;
    }

    // ══════════════════ IDE: боковая панель (скелет + подсказки) ══════════════════

    const SKEL_SLOTS = [
        { slot: 'filter', label: 'Фильтр', hint: '--filter-tcp/udp/l7' },
        { slot: 'list',   label: 'Домены/IP', hint: '--hostlist / --ipset' },
        { slot: 'range',  label: 'Диапазон/payload', hint: '--out-range / --payload' },
        { slot: 'desync', label: 'Действие', hint: '--lua-desync=…' },
    ];

    function renderSidePanel() {
        const el = document.getElementById('editor-sidepanel');
        if (!el) return;
        const idx = editorActive.index;
        const profiles = (editorData && editorData.profiles) || [];
        const item = document.querySelector('.profile-editor-item[data-index="' + idx + '"]');
        const args = profiles[idx] ? (profiles[idx].args || '') : '';
        let analysis = item && item._analysis ? item._analysis : null;
        if (!analysis) { try { analysis = Nfqws2Lint.analyze(args); } catch (_e) { analysis = { slots: new Set(), diagnostics: [] }; } }

        let doc = null;
        try { doc = Nfqws2Lint.docAt(args, editorActive.cursor); } catch (_e) { doc = null; }

        el.innerHTML =
            renderSkeletonHtml(analysis, profiles.length, idx)
            + renderTokenDocHtml(doc)
            + renderDiagListHtml(analysis, idx);
    }

    function renderSkeletonHtml(analysis, profileCount, idx) {
        const chips = SKEL_SLOTS.map((s, i) => {
            const filled = analysis.slots && analysis.slots.has(s.slot);
            const arrow = i > 0 ? '<span class="nfq-skel-arrow">→</span>' : '';
            return arrow + '<span class="nfq-skel-chip' + (filled ? ' filled' : '')
                + '" title="' + escapeHtml(s.hint) + '">' + escapeHtml(s.label) + '</span>';
        }).join('');
        const multi = profileCount > 1
            ? '<div class="nfq-side-sub">Профиль ' + (idx + 1) + ' из ' + profileCount
              + ' · профили разделяются <code>--new</code></div>'
            : '';
        return '<div class="nfq-side-card nfq-side-skel">'
            + '<div class="nfq-side-title">Скелет стратегии nfqws2</div>'
            + '<div class="nfq-skel-flow">' + chips + '</div>'
            + '<div class="nfq-side-note">Порядок внутри профиля: фильтр → домены/IP → '
            + 'диапазон/payload → действие. Блобы <code>--blob=</code> — в начало, до '
            + 'первого <code>--new</code>.</div>'
            + multi
            + '</div>';
    }

    function renderTokenDocHtml(doc) {
        if (!doc) {
            return '<div class="nfq-side-card nfq-side-doc nfq-side-doc-empty">'
                + '<div class="nfq-side-title">Подсказка по коду</div>'
                + '<div class="nfq-side-note">Поставьте курсор на флаг, функцию или параметр — '
                + 'здесь появится его описание, тип и допустимые значения. '
                + 'Автодополнение: <kbd>Ctrl</kbd>+<kbd>Space</kbd> или «=».</div></div>';
        }
        const parts = [];
        parts.push('<div class="nfq-side-title">' + escapeHtml(doc.title || '')
            + (doc.kind === 'func' ? ' <span class="nfq-doc-tag">функция</span>' : '')
            + (doc.kind === 'flag' ? ' <span class="nfq-doc-tag">флаг</span>' : '')
            + (doc.kind === 'subarg' ? ' <span class="nfq-doc-tag">параметр</span>' : '')
            + '</div>');
        if (doc.signature)
            parts.push('<div class="nfq-doc-sig"><code>' + escapeHtml(doc.signature) + '</code></div>');
        if (doc.desc)
            parts.push('<div class="nfq-doc-desc">' + escapeHtml(doc.desc) + '</div>');
        const meta = [];
        if (doc.type) meta.push('тип: <code>' + escapeHtml(doc.type) + '</code>');
        if (doc.file) meta.push('из <code>' + escapeHtml(doc.file) + '</code>');
        if (doc.group && doc.group !== 'arg') meta.push('группа: <code>' + escapeHtml(doc.group) + '</code>');
        if (doc.payload) meta.push('payload: <code>' + escapeHtml(doc.payload) + '</code>');
        if (meta.length) parts.push('<div class="nfq-doc-meta">' + meta.join(' · ') + '</div>');
        if (doc.values && doc.values.length) {
            const vals = doc.values.slice(0, 24).map(v => '<code class="nfq-doc-val">' + escapeHtml(String(v)) + '</code>').join(' ');
            parts.push('<div class="nfq-doc-vals"><span class="nfq-doc-label">значения:</span> ' + vals
                + (doc.values.length > 24 ? ' …' : '') + '</div>');
        }
        if (doc.examples && doc.examples.length)
            parts.push('<div class="nfq-doc-vals"><span class="nfq-doc-label">примеры:</span> '
                + doc.examples.map(v => '<code class="nfq-doc-val">' + escapeHtml(String(v)) + '</code>').join(' ') + '</div>');
        if (doc.groups && doc.groups.length)
            parts.push('<div class="nfq-doc-meta">принимает опции: ' + doc.groups.map(g => '<code>' + escapeHtml(g) + '</code>').join(', ') + '</div>');
        if (doc.argList && doc.argList.length) {
            const rows = doc.argList.map(a =>
                '<div class="nfq-doc-arg"><code>' + escapeHtml(a.name) + '</code>'
                + '<span class="nfq-doc-arg-type">' + escapeHtml(a.type || '') + '</span>'
                + (a.desc ? '<span class="nfq-doc-arg-desc">' + escapeHtml(a.desc) + '</span>' : '') + '</div>').join('');
            parts.push('<div class="nfq-doc-args"><div class="nfq-doc-label">параметры:</div>' + rows + '</div>');
        }
        return '<div class="nfq-side-card nfq-side-doc">' + parts.join('') + '</div>';
    }

    function renderDiagListHtml(analysis, idx) {
        const diags = (analysis && analysis.diagnostics) || [];
        if (!diags.length) {
            return '<div class="nfq-side-card nfq-side-diag nfq-diag-ok">'
                + '<div class="nfq-side-title">Проверка синтаксиса</div>'
                + '<div class="nfq-diag-ok-row">✓ Ошибок не найдено</div></div>';
        }
        const order = { error: 0, warn: 1, info: 2 };
        const icon = { error: '✕', warn: '⚠', info: 'ℹ' };
        const sorted = diags.slice().sort((a, b) => (order[a.severity] - order[b.severity]) || (a.start - b.start));
        const rows = sorted.map(d => {
            const jump = (!d.structural && d.end > d.start)
                ? ' onclick="StrategiesPage.jumpToDiag(' + idx + ',' + d.start + ',' + d.end + ')" style="cursor:pointer;"'
                : '';
            return '<div class="nfq-diag-row nfq-diag-' + d.severity + '"' + jump + '>'
                + '<span class="nfq-diag-ico">' + icon[d.severity] + '</span>'
                + '<span class="nfq-diag-msg">' + escapeHtml(d.message) + '</span></div>';
        }).join('');
        const nErr = diags.filter(d => d.severity === 'error').length;
        const nWarn = diags.filter(d => d.severity === 'warn').length;
        const summary = (nErr ? nErr + ' ошиб. ' : '') + (nWarn ? nWarn + ' предупр.' : '');
        return '<div class="nfq-side-card nfq-side-diag">'
            + '<div class="nfq-side-title">Проверка синтаксиса '
            + (summary ? '<span class="nfq-diag-sum">' + escapeHtml(summary.trim()) + '</span>' : '') + '</div>'
            + rows + '</div>';
    }

    // Перейти к проблемному месту: выделить диапазон в textarea активного профиля.
    function jumpToDiag(index, start, end) {
        editorActive.index = index;
        const item = document.querySelector('.profile-editor-item[data-index="' + index + '"]');
        const ta = item && item.querySelector('.profile-args');
        if (!ta) return;
        ta.focus();
        try { ta.setSelectionRange(start, end); } catch (_e) { /* ignore */ }
        editorActive.cursor = start;
        renderSidePanel();
    }

    function closeModal() {
        NfqwsAutocomplete.detachAll();
        disableModalResize();
        const modal = document.getElementById('strategy-modal');
        if (modal) modal.style.display = 'none';
        editorData = null;
        // Сбрасываем отложенный коллбэк объединения, чтобы он не выстрелил
        // на следующем (несвязанном) сохранении.
        editorOnSaved = null;
    }

    // ══════════════════ Буфер обмена: копирование/вставка стратегий (§3) ══════════════════

    // Копировать выбранную стратегию со всеми профилями (через --new) в буфер.
    function copyStrategyToClipboard(sid) {
        const s = strategies.find(x => x.id === sid);
        if (!s) return;
        const parts = (s.profiles || []).map(p => (p.args || '').trim()).filter(Boolean);
        if (!parts.length) { Toast.warning('У стратегии нет аргументов для копирования'); return; }
        const text = parts.join(' --new ');
        _copyText(text, 'Стратегия скопирована в буфер (профилей: ' + parts.length + ')');
    }

    // Вставка по кнопке: пытаемся прочитать буфер (в secure-context). На роутере
    // по http navigator.clipboard.readText недоступен — подсказываем Ctrl+V,
    // который работает через событие paste (см. attachGlobalKeys).
    async function pasteStrategyFromClipboard() {
        let text = '';
        try {
            if (navigator.clipboard && navigator.clipboard.readText) {
                text = await navigator.clipboard.readText();
            }
        } catch (_e) { /* доступ к буферу запрещён */ }
        if (!text) {
            Toast.info('Скопируйте стратегию и нажмите Ctrl+V на этой странице');
            return;
        }
        if (!_looksLikeStrategy(text)) {
            Toast.warning('В буфере нет распознаваемой стратегии nfqws2');
            return;
        }
        _openPasteEditor(text);
    }

    // Эвристика: похоже ли содержимое буфера на стратегию nfqws2.
    function _looksLikeStrategy(text) {
        return /--(?:lua-desync|dpi-desync|filter-(?:tcp|udp|l7|l3)|new|hostlist|payload|wssize|dup)\b/.test(String(text || ''));
    }

    // Разбить строку args по разделителю профилей --new.
    function _splitNew(s) {
        return String(s || '').split(/\s+--new\s+/).map(x => x.trim()).filter(Boolean);
    }

    // Имя/id профиля из его args (зеркалит backend _detect_profile_info).
    function _detectProfileInfo(argStr, idx) {
        const toks = String(argStr || '').split(/\s+/);
        for (const t of toks) {
            if (t.startsWith('--filter-tcp=')) {
                const port = t.split('=')[1] || '';
                if (port === '80') return ['http' + (idx + 1), 'HTTP (порт 80)'];
                return ['tcp' + (idx + 1), 'TCP (порты ' + port + ')'];
            }
            if (t.startsWith('--filter-udp=')) {
                const port = t.split('=')[1] || '';
                return ['udp' + (idx + 1), 'UDP (порты ' + port + ')'];
            }
            if (t.startsWith('--filter-l3=')) {
                const ver = t.split('=')[1] || '';
                return [ver + '_' + (idx + 1), ver.toUpperCase()];
            }
        }
        return ['profile' + (idx + 1), 'Профиль ' + (idx + 1)];
    }

    // Распарсить текст из буфера в массив профилей. Поддерживает наш формат
    // (args --new args) и блочный вывод blockcheck2 (строки «nfqws2 args»,
    // комментарии «# …» игнорируются).
    function _parseStrategyArgs(text) {
        const lines = String(text || '').split('\n')
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('#'));
        const segs = [];
        lines.forEach(line => {
            const noEngine = line.replace(/^(?:nfqws2?|winws2?)\s+/i, '');
            _splitNew(noEngine).forEach(seg => { if (seg) segs.push(seg); });
        });
        return segs.map((argStr, i) => {
            const info = _detectProfileInfo(argStr, i);
            return { id: info[0], name: info[1], enabled: true, args: argStr };
        });
    }

    // Открыть редактор СОЗДАНИЯ, предзаполненный профилями из буфера.
    // Автоматически НЕ сохраняем — решение за пользователем (§3).
    function _openPasteEditor(text) {
        const profiles = _parseStrategyArgs(text);
        if (!profiles.length) { Toast.warning('В буфере нет распознаваемой стратегии'); return; }
        openEditor({
            id: '',
            name: '',
            description: 'Вставлено из буфера обмена',
            type: profiles.length > 1 ? 'combined' : 'single',
            profiles,
        }, 'create');
        Toast.info('Стратегия из буфера — задайте ID/имя, проверьте и сохраните');
    }

    // Копирование в буфер с fallback на execCommand (работает и по http,
    // где navigator.clipboard недоступен).
    function _copyText(text, okMsg) {
        const done = () => Toast.success(okMsg || 'Скопировано');
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(() => _copyFallback(text, done));
        } else {
            _copyFallback(text, done);
        }
    }
    function _copyFallback(text, done) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            done();
        } catch (_e) {
            Toast.error('Не удалось скопировать');
        }
    }

    // ══════════════════ Множественный выбор и объединение (§7) ══════════════════

    function toggleSelect(ev, id) {
        if (ev) ev.stopPropagation();
        const checked = ev && ev.target ? !!ev.target.checked : !selectedIds.has(id);
        if (checked) selectedIds.add(id); else selectedIds.delete(id);
        const card = ev && ev.target && ev.target.closest('.strategy-card');
        if (card) card.classList.toggle('selected', checked);
        renderBulkBar();
    }

    function clearSelection() {
        selectedIds.clear();
        document.querySelectorAll('.strategy-select').forEach(c => { c.checked = false; });
        document.querySelectorAll('.strategy-card.selected').forEach(c => c.classList.remove('selected'));
        renderBulkBar();
    }

    function renderBulkBar() {
        const bar = document.getElementById('strat-bulkbar');
        if (!bar) return;
        const n = selectedIds.size;
        if (n === 0) { bar.style.display = 'none'; bar.innerHTML = ''; return; }
        const canMerge = n >= 2;
        bar.style.display = 'flex';
        bar.innerHTML = `
            <span class="strat-bulkbar-count">Выбрано: <b>${n}</b></span>
            <button class="btn btn-primary btn-sm" onclick="StrategiesPage.mergeSelected()"
                    ${canMerge ? '' : 'disabled'}
                    title="${canMerge ? 'Объединить выбранные стратегии в одну (профили сложатся)' : 'Выберите минимум 2 стратегии'}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" style="margin-right:4px;">
                    <polyline points="8 17 12 21 16 17"/><line x1="12" y1="21" x2="12" y2="9"/>
                    <path d="M5 9a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4"/>
                </svg>
                Объединить
            </button>
            <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.clearSelection()">Снять выделение</button>
        `;
    }

    // Объединить выбранные стратегии: открываем редактор СОЗДАНИЯ с суммой их
    // профилей. После сохранения предложим удалить исходные (§7).
    function mergeSelected() {
        const ids = Array.from(selectedIds);
        if (ids.length < 2) { Toast.warning('Выберите минимум 2 стратегии'); return; }
        const sources = ids.map(id => strategies.find(s => s.id === id)).filter(Boolean);
        if (sources.length < 2) { Toast.error('Не удалось найти выбранные стратегии'); return; }

        const profiles = [];
        sources.forEach(s => {
            (s.profiles || []).forEach(p => {
                profiles.push({
                    id: '',  // переназначится в saveEditor
                    name: p.name || p.id || 'Профиль',
                    enabled: p.enabled !== false,
                    args: p.args || '',
                });
            });
        });

        const name = sources.map(s => s.name).join(' + ');
        const baseId = ('merged_' + sources.map(s => String(s.id).replace(/[^a-zA-Z0-9_-]/g, '')).join('_'))
            .slice(0, 48);

        // Источники для возможного удаления после сохранения. Захватываем в
        // замыкание, т.к. closeModal сбрасывает editorOnSaved до вызова коллбэка.
        const userIds = sources.filter(s => !s.is_builtin).map(s => s.id);
        const builtinKept = sources.filter(s => s.is_builtin).map(s => s.name);
        editorOnSaved = () => afterMergeSave(userIds, builtinKept);

        openEditor({
            id: baseId,
            name: name.slice(0, 120),
            description: 'Объединено из: ' + sources.map(s => s.name).join(', '),
            type: 'combined',
            profiles,
        }, 'create');
        Toast.info('Проверьте объединённую стратегию (ID/имя/профили) и сохраните');
    }

    // После успешного сохранения объединённой стратегии — предложить удалить
    // исходные (только пользовательские; встроенные удалить нельзя).
    function afterMergeSave(toDelete, builtinKept) {
        toDelete = (toDelete || []).slice();
        builtinKept = (builtinKept || []).slice();

        if (!toDelete.length) {
            if (builtinKept.length) {
                Toast.info('Встроенные стратегии не удаляются: ' + builtinKept.join(', '));
            }
            clearSelection();
            return;
        }
        let msg = 'Объединённая стратегия создана.\n\nУдалить исходные стратегии (' + toDelete.length + ' шт.)?';
        if (builtinKept.length) {
            msg += '\n\nВстроенные нельзя удалить, они останутся: ' + builtinKept.join(', ');
        }
        if (!confirm(msg)) { clearSelection(); return; }
        deleteStrategiesSeq(toDelete);
    }

    async function deleteStrategiesSeq(ids) {
        let ok = 0, fail = 0;
        for (const id of ids) {
            try {
                const r = await API.delete('/api/strategies/' + encodeURIComponent(id));
                if (r && r.ok) ok++; else fail++;
            } catch (_e) { fail++; }
        }
        if (ok) Toast.success('Удалено исходных стратегий: ' + ok);
        if (fail) Toast.error('Не удалось удалить: ' + fail);
        clearSelection();
        fetchStrategies();
    }

    // ══════════════════ Глобальные клавиши: ESC (§4) + Ctrl+V (§3) ══════════════════

    function _modalOpen(el) {
        return !!(el && el.style && el.style.display && el.style.display !== 'none');
    }
    function _anyModalOpen() {
        return _modalOpen(document.getElementById('strategy-modal'))
            || _modalOpen(document.getElementById('preview-modal'));
    }

    function attachGlobalKeys() {
        detachGlobalKeys();
        escKeyHandler = (e) => {
            if (e.key !== 'Escape' || e.defaultPrevented) return; // autocomplete и т.п. уже обработали
            if (_modalOpen(document.getElementById('strategy-modal'))) {
                e.preventDefault();
                closeModal();
            } else if (_modalOpen(document.getElementById('preview-modal'))) {
                e.preventDefault();
                closePreview();
            }
        };
        pasteHandler = (e) => {
            const t = e.target;
            // Не мешаем обычной вставке в поля ввода и при открытых окнах.
            if (t && (t.closest && t.closest('input, textarea, select') || t.isContentEditable)) return;
            if (_anyModalOpen()) return;
            const cd = e.clipboardData || window.clipboardData;
            const text = cd && cd.getData ? cd.getData('text') : '';
            if (!text || !_looksLikeStrategy(text)) return;
            e.preventDefault();
            _openPasteEditor(text);
        };
        document.addEventListener('keydown', escKeyHandler);
        document.addEventListener('paste', pasteHandler);
    }

    function detachGlobalKeys() {
        if (escKeyHandler) document.removeEventListener('keydown', escKeyHandler);
        if (pasteHandler) document.removeEventListener('paste', pasteHandler);
        escKeyHandler = null;
        pasteHandler = null;
    }

    // ══════════════════ Ресайз/перемещение окна редактора (§5) ══════════════════

    const MODAL_GEOM_KEY = 'strategy-modal-geom';
    const MODAL_MIN_W = 420;
    const MODAL_MIN_H = 240;

    // Начальная геометрия: сохранённая пользователем (если есть) либо дефолт —
    // ширина 2× прежней (modal-lg=680 → 1360), высота по содержимому формы,
    // окно по центру. Содержимое измеряем при целевой ширине (§5).
    function _initialGeom(content) {
        const saved = _loadModalGeom();
        if (saved) return _clampGeom(saved);
        const vw = window.innerWidth, vh = window.innerHeight;
        const width = Math.min(1360, Math.max(MODAL_MIN_W, vw - 40));
        // Меряем естественную высоту при заданной ширине.
        content.style.left = '0px';
        content.style.top = '0px';
        content.style.width = width + 'px';
        content.style.height = '';
        const natural = content.scrollHeight;
        const height = Math.min(Math.max(MODAL_MIN_H, natural + 2),
            Math.round(vh * 0.92), vh - 24);
        const left = Math.max(12, Math.round((vw - width) / 2));
        const top = Math.max(12, Math.round((vh - height) / 2));
        return { left, top, width, height };
    }
    function _loadModalGeom() {
        try {
            const g = JSON.parse(localStorage.getItem(MODAL_GEOM_KEY) || 'null');
            if (g && typeof g.width === 'number' && typeof g.height === 'number') return g;
        } catch (_e) { /* ignore */ }
        return null;
    }
    function _saveModalGeom(g) {
        try { localStorage.setItem(MODAL_GEOM_KEY, JSON.stringify(g)); } catch (_e) { /* quota */ }
    }
    function _curGeom(el) {
        const r = el.getBoundingClientRect();
        return { left: r.left, top: r.top, width: r.width, height: r.height };
    }
    function _clampGeom(g) {
        const vw = window.innerWidth, vh = window.innerHeight;
        const width = Math.max(MODAL_MIN_W, Math.min(g.width, vw - 16));
        const height = Math.max(MODAL_MIN_H, Math.min(g.height, vh - 16));
        const left = Math.min(Math.max(8, g.left), Math.max(8, vw - width - 8));
        const top = Math.min(Math.max(8, g.top), Math.max(8, vh - height - 8));
        return { left, top, width, height };
    }
    function _applyGeom(el, g) {
        el.style.left = g.left + 'px';
        el.style.top = g.top + 'px';
        el.style.width = g.width + 'px';
        el.style.height = g.height + 'px';
    }

    function enableModalResize() {
        const modal = document.getElementById('strategy-modal');
        if (!modal) return;
        const content = modal.querySelector('.modal-content');
        if (!content) return;
        disableModalResize();
        content.classList.add('modal-resizable');

        _applyGeom(content, _initialGeom(content));

        const dirs = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];
        const handles = dirs.map(dir => {
            const h = document.createElement('div');
            h.className = 'modal-resize-handle mrh-' + dir;
            h.addEventListener('pointerdown', (e) => startResize(e, content, dir));
            content.appendChild(h);
            return h;
        });

        const header = content.querySelector('.modal-header');
        const onHeaderDown = (e) => startMove(e, content);
        if (header) header.addEventListener('pointerdown', onHeaderDown);

        const onWinResize = () => _applyGeom(content, _clampGeom(_curGeom(content)));
        window.addEventListener('resize', onWinResize);

        modalResize = {
            cleanup() {
                handles.forEach(h => h.remove());
                if (header) header.removeEventListener('pointerdown', onHeaderDown);
                window.removeEventListener('resize', onWinResize);
                content.classList.remove('modal-resizable');
                content.style.left = content.style.top = content.style.width = content.style.height = '';
            },
        };
    }

    function disableModalResize() {
        if (modalResize) {
            try { modalResize.cleanup(); } catch (_e) { /* ignore */ }
            modalResize = null;
        }
    }

    function startResize(e, el, dir) {
        if (e.button != null && e.button !== 0) return;
        e.preventDefault();
        e.stopPropagation();
        const sx = e.clientX, sy = e.clientY;
        const s = _curGeom(el);
        const move = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            let { left, top, width, height } = s;
            if (dir.indexOf('e') >= 0) width = s.width + dx;
            if (dir.indexOf('s') >= 0) height = s.height + dy;
            if (dir.indexOf('w') >= 0) { width = s.width - dx; left = s.left + dx; }
            if (dir.indexOf('n') >= 0) { height = s.height - dy; top = s.top + dy; }
            if (width < MODAL_MIN_W) {
                if (dir.indexOf('w') >= 0) left = s.left + (s.width - MODAL_MIN_W);
                width = MODAL_MIN_W;
            }
            if (height < MODAL_MIN_H) {
                if (dir.indexOf('n') >= 0) top = s.top + (s.height - MODAL_MIN_H);
                height = MODAL_MIN_H;
            }
            _applyGeom(el, { left, top, width, height });
        };
        const up = () => {
            document.removeEventListener('pointermove', move);
            document.removeEventListener('pointerup', up);
            _saveModalGeom(_clampGeom(_curGeom(el)));
        };
        document.addEventListener('pointermove', move);
        document.addEventListener('pointerup', up);
    }

    function startMove(e, el) {
        // Не таскаем, если ухватились за кнопку/поле в шапке.
        if (e.target && e.target.closest && e.target.closest('.modal-close, button, input, select, textarea, a')) return;
        if (e.button != null && e.button !== 0) return;
        e.preventDefault();
        const sx = e.clientX, sy = e.clientY;
        const s = _curGeom(el);
        const move = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            _applyGeom(el, _clampGeom({ left: s.left + dx, top: s.top + dy, width: s.width, height: s.height }));
        };
        const up = () => {
            document.removeEventListener('pointermove', move);
            document.removeEventListener('pointerup', up);
            _saveModalGeom(_curGeom(el));
        };
        document.addEventListener('pointermove', move);
        document.addEventListener('pointerup', up);
    }

    // ══════════════════ Utils ══════════════════

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function destroy() {
        NfqwsAutocomplete.detachAll();
        detachGlobalKeys();
        disableModalResize();
        selectedIds.clear();
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
        if (catalogPollTimer) {
            clearInterval(catalogPollTimer);
            catalogPollTimer = null;
        }
        if (healthcheckPollTimer) {
            clearInterval(healthcheckPollTimer);
            healthcheckPollTimer = null;
        }
        if (listUI) {
            try { listUI.destroy(); } catch (_e) {}
            listUI = null;
        }
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        setFilter,
        applyStrategy,
        toggleFavorite,
        deleteStrategy,
        duplicateStrategy,
        showPreview,
        validatePreview,
        closePreview,
        copyPreview,
        openCreate,
        openEdit,
        closeModal,
        addProfile,
        removeProfile,
        toggleProfile,
        updateProfileName,
        updateProfileArgs,
        insertHostlist,
        insertFilter,
        jumpToDiag,
        prefillCreate,
        editorPreview,
        saveEditor,
        updateCatalog,
        toggleDebug,
        openLogs,
        refreshState,
        clearAllState,
        clearHostState,
        clearKeyState,
        showCircularStrategies,
        refreshHealthcheck,
        toggleHealthcheck,
        runHealthcheckNow,
        toggleHealthcheckSettings,
        saveHealthcheckSettings,
        // §3 буфер обмена
        copyStrategyToClipboard,
        pasteStrategyFromClipboard,
        // §7 множественный выбор / объединение
        toggleSelect,
        clearSelection,
        mergeSelected,
    };
})();
