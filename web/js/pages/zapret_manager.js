/**
 * zapret_manager.js — Управление zapret2 (nfqws2).
 *
 * Функции:
 *   - Отображение текущей и последней версий
 *   - Установка zapret2 (если не установлен)
 *   - Обновление до последней версии
 *   - Удаление zapret2 с предварительным показом плана
 *   - Автоматическая проверка обновлений при открытии страницы
 *   - Прогресс-бар для длительных операций
 */

const ZapretManagerPage = (() => {
    // ══════════════════ State ══════════════════

    let data = null;
    let pollTimer = null;
    let progressTimer = null;
    let guiProgressTimer = null;
    let isOperationRunning = false;
    let guiUpdateRunning = false;

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Управление zapret2</h1>
                    <p class="page-description">Установка, обновление и удаление движка nfqws2</p>
                </div>
                <button class="btn btn-ghost btn-sm" onclick="ZapretManagerPage.refresh()" id="zm-btn-refresh">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                    </svg>
                    Проверить
                </button>
            </div>

            <!-- Баннер обновления GUI -->
            <div class="card hidden" id="gui-update-banner"
                 style="background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.1));
                        border: 1px solid rgba(99,102,241,0.3); margin-bottom: 16px;">
                <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-weight:600; color:var(--primary);">Доступна новая версия zapret-gui</span>
                        <span style="color:var(--text-secondary); font-size:13px; margin-left:8px;">
                            v<span id="gui-update-version">?</span>
                        </span>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="ZapretManagerPage.updateGui()">
                        Обновить GUI
                    </button>
                </div>
            </div>

            <!-- Статус версий -->
            <div class="status-grid" id="zm-version-grid">
                <div class="status-card" id="zm-card-installed">
                    <div class="status-card-header">
                        <span class="status-dot stopped" id="zm-installed-dot"></span>
                        <span class="status-card-label">Установленная версия</span>
                    </div>
                    <div class="status-card-value" id="zm-installed-version" style="font-size: 18px;">—</div>
                    <div class="status-card-detail" id="zm-installed-detail">Загрузка...</div>
                </div>

                <div class="status-card" id="zm-card-latest">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="12" y1="16" x2="12" y2="12"/>
                                <line x1="12" y1="8" x2="12.01" y2="8"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Последняя версия</span>
                    </div>
                    <div class="status-card-value" id="zm-latest-version" style="font-size: 18px;">—</div>
                    <div class="status-card-detail" id="zm-latest-detail">Загрузка...</div>
                </div>

                <div class="status-card" id="zm-card-process">
                    <div class="status-card-header">
                        <span class="status-dot stopped" id="zm-process-dot"></span>
                        <span class="status-card-label">Процесс nfqws2</span>
                    </div>
                    <div class="status-card-value" id="zm-process-status">—</div>
                    <div class="status-card-detail" id="zm-process-detail"></div>
                </div>

                <div class="status-card" id="zm-card-platform">
                    <div class="status-card-header">
                        <span class="status-card-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                <line x1="8" y1="21" x2="16" y2="21"/>
                                <line x1="12" y1="17" x2="12" y2="21"/>
                            </svg>
                        </span>
                        <span class="status-card-label">Платформа</span>
                    </div>
                    <div class="status-card-value" id="zm-platform" style="font-size: 14px;">—</div>
                    <div class="status-card-detail" id="zm-arch"></div>
                </div>
            </div>

            <!-- Уведомление об обновлении -->
            <div class="card zm-update-banner hidden" id="zm-update-banner">
                <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 200px;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2" width="18" height="18">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                <polyline points="7 10 12 15 17 10"/>
                                <line x1="12" y1="15" x2="12" y2="3"/>
                            </svg>
                            <span style="font-size: 14px; font-weight: 600; color: var(--warning);">Доступно обновление</span>
                        </div>
                        <span style="font-size: 13px; color: var(--text-secondary);" id="zm-update-detail">
                            Новая версия доступна для загрузки
                        </span>
                    </div>
                    <button class="btn btn-sm" style="background: var(--warning); color: #000; font-weight: 600;"
                            onclick="ZapretManagerPage.doUpdate()" id="zm-btn-update-banner">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Обновить
                    </button>
                </div>
            </div>

            <!-- Прогресс операции -->
            <div class="card hidden" id="zm-progress-card" style="padding: 20px;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                    <span class="spinner" style="width: 18px; height: 18px; border-width: 2px;" id="zm-progress-spinner"></span>
                    <span style="font-size: 14px; font-weight: 500; color: var(--text-primary);" id="zm-progress-title">Выполняется операция...</span>
                </div>
                <div class="zm-progress-track">
                    <div class="zm-progress-bar" id="zm-progress-bar" style="width: 0%;"></div>
                </div>
                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;" id="zm-progress-text">Подготовка...</div>
            </div>

            <!-- Действия -->
            <div class="card" style="margin-top: 16px; padding: 16px 20px;" id="zm-actions-card">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                    </svg>
                    Действия
                </div>
                <div class="actions-row" style="margin-top: 12px;" id="zm-actions">
                    <!-- Кнопки формируются динамически -->
                </div>
            </div>

            <!-- Информация о релизе -->
            <div class="card hidden" id="zm-release-info" style="margin-top: 16px; padding: 16px 20px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    Информация о релизе
                </div>
                <div id="zm-release-body" style="margin-top: 10px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;"></div>
                <div style="margin-top: 10px;">
                    <a id="zm-release-link" href="#" target="_blank" rel="noopener"
                       style="font-size: 12px; color: var(--accent); text-decoration: none;">
                        Открыть на GitHub →
                    </a>
                </div>
            </div>

            <!-- Подсказка -->
            <div class="card" style="margin-top: 16px; padding: 16px 20px; border-left: 3px solid var(--info);">
                <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                    <strong style="color: var(--info);">Информация</strong><br>
                    Zapret2 (nfqws2) — движок DPI-обхода, который запускается на роутере.
                    Эта страница позволяет управлять его установкой и обновлениями.
                    Репозиторий:
                    <a href="https://github.com/bol-van/zapret2" target="_blank" rel="noopener"
                       style="color: var(--accent); text-decoration: none;">github.com/bol-van/zapret2</a>
                </div>
            </div>

            <!-- Модальное окно подтверждения удаления -->
            <div class="modal-backdrop hidden" id="zm-uninstall-modal" onclick="ZapretManagerPage.closeUninstallModal(event)">
                <div class="modal-content" onclick="event.stopPropagation()" style="max-width: 520px;">
                    <div class="modal-header">
                        <h3 style="color: var(--error);">Удаление zapret2</h3>
                        <button class="btn btn-ghost btn-sm" onclick="ZapretManagerPage.closeUninstallModal()" style="margin-left:auto;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body" style="padding: 16px 20px;">
                        <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 12px; font-weight: 500;">
                            Будут удалены следующие элементы:
                        </div>
                        <div id="zm-uninstall-list" style="max-height: 250px; overflow-y: auto;"></div>
                        <div id="zm-uninstall-warnings" style="margin-top: 12px;"></div>
                        <div style="display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end;">
                            <button class="btn btn-ghost" onclick="ZapretManagerPage.closeUninstallModal()">Отмена</button>
                            <button class="btn btn-danger" onclick="ZapretManagerPage.confirmUninstall()" id="zm-btn-confirm-uninstall">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                                Удалить
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Загружаем данные
        loadData();
        startPoll();
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadData() {
        try {
            data = await API.get('/api/zapret');
            if (data.ok) {
                renderData();
            }
        } catch (err) {
            setError('Ошибка загрузки: ' + err.message);
        }

        // Проверка обновлений GUI (не блокирует основную загрузку)
        try {
            const guiCheck = await API.get('/api/gui/check');
            if (guiCheck.update_available) {
                showGuiUpdateBanner(guiCheck);
            }
        } catch (e) {
            // Не критично — молча пропускаем
        }
    }

    function renderData() {
        if (!data) return;

        const inst = data.installed || {};
        const lat = data.latest || {};
        const running = data.nfqws_running || {};
        const op = data.operation || {};

        // ── Установленная версия ──
        const instDot = document.getElementById('zm-installed-dot');
        const instVer = document.getElementById('zm-installed-version');
        const instDetail = document.getElementById('zm-installed-detail');

        if (inst.installed) {
            if (instDot) instDot.className = 'status-dot running';
            if (instVer) {
                instVer.textContent = inst.version || '?';
                instVer.style.color = 'var(--success)';
            }
            if (instDetail) {
                instDetail.textContent = 'Установлен • ' + (inst.base_path || '/opt/zapret2');
            }
        } else {
            if (instDot) instDot.className = 'status-dot stopped';
            if (instVer) {
                instVer.textContent = 'Не установлен';
                instVer.style.color = 'var(--error)';
            }
            if (instDetail) instDetail.textContent = 'Требуется установка';
        }

        // ── Последняя версия ──
        const latVer = document.getElementById('zm-latest-version');
        const latDetail = document.getElementById('zm-latest-detail');

        if (lat.ok && lat.version) {
            if (latVer) {
                latVer.textContent = lat.version;
                latVer.style.color = 'var(--accent)';
            }
            if (latDetail) {
                const date = lat.published_at ? formatDate(lat.published_at) : '';
                latDetail.textContent = date ? ('Выпущена ' + date) : 'GitHub Releases';
            }
        } else {
            if (latVer) {
                latVer.textContent = lat.error ? 'Ошибка' : '—';
                latVer.style.color = lat.error ? 'var(--error)' : 'var(--text-muted)';
            }
            if (latDetail) {
                latDetail.textContent = lat.error || 'Не удалось проверить';
            }
        }

        // ── Процесс nfqws2 ──
        const procDot = document.getElementById('zm-process-dot');
        const procStatus = document.getElementById('zm-process-status');
        const procDetail = document.getElementById('zm-process-detail');

        if (running.running) {
            if (procDot) procDot.className = 'status-dot running';
            if (procStatus) {
                procStatus.textContent = 'Запущен';
                procStatus.className = 'status-card-value running';
            }
            if (procDetail) {
                procDetail.textContent = 'PID ' + (running.pid || '?') +
                    (running.source === 'manager' ? ' (GUI)' : ' (система)');
            }
        } else {
            if (procDot) procDot.className = 'status-dot stopped';
            if (procStatus) {
                procStatus.textContent = 'Остановлен';
                procStatus.className = 'status-card-value stopped';
            }
            if (procDetail) procDetail.textContent = '';
        }

        // ── Платформа ──
        const platEl = document.getElementById('zm-platform');
        const archEl = document.getElementById('zm-arch');
        if (platEl) platEl.textContent = data.platform || '—';
        if (archEl) archEl.textContent = data.arch || '';

        // ── Баннер обновления ──
        const banner = document.getElementById('zm-update-banner');
        if (banner) {
            if (data.update_available) {
                banner.classList.remove('hidden');
                const detail = document.getElementById('zm-update-detail');
                if (detail) {
                    detail.textContent = (inst.version || '?') + ' → ' + (lat.version || '?');
                }
            } else {
                banner.classList.add('hidden');
            }
        }

        // ── Прогресс операции ──
        if (op.in_progress) {
            showProgress(op.status, op.progress);
            if (!progressTimer) {
                startProgressPolling();
            }
        } else {
            hideProgress();
        }

        // ── Кнопки действий ──
        renderActions();

        // ── Информация о релизе ──
        renderReleaseInfo();
    }

    function renderActions() {
        const container = document.getElementById('zm-actions');
        if (!container || !data) return;

        const inst = data.installed || {};
        const running = data.nfqws_running || {};
        const op = data.operation || {};
        const disabled = op.in_progress || isOperationRunning;
        const updateDisabled = disabled || !data.update_available;

        let html = '';

        if (!inst.installed) {
            // Не установлен — показываем кнопку установки
            html = `
                <button class="btn btn-success" onclick="ZapretManagerPage.doInstall()" ${disabled ? 'disabled' : ''} id="zm-btn-install">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Установить zapret2
                </button>
            `;
        } else {
            // Установлен — обновление и удаление
            html = `
                <button class="btn btn-primary" onclick="ZapretManagerPage.doUpdate()" ${updateDisabled ? 'disabled' : ''} id="zm-btn-update">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Обновить
                </button>
                <button class="btn btn-danger" onclick="ZapretManagerPage.showUninstallPlan()" ${disabled ? 'disabled' : ''} id="zm-btn-uninstall">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polyline points="3 6 5 6 21 6"/>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                    </svg>
                    Удалить
                </button>
            `;
        }

        container.innerHTML = html;
    }

    function renderReleaseInfo() {
        const card = document.getElementById('zm-release-info');
        const body = document.getElementById('zm-release-body');
        const link = document.getElementById('zm-release-link');
        if (!card || !data) return;

        const lat = data.latest || {};

        if (lat.ok && lat.description) {
            card.classList.remove('hidden');
            if (body) {
                // Ограничиваем описание и escapeHtml
                const desc = escapeHtml(lat.description.substring(0, 500));
                body.innerHTML = desc.replace(/\n/g, '<br>');
            }
            if (link) {
                link.href = lat.release_url || 'https://github.com/bol-van/zapret2/releases';
            }
        } else {
            card.classList.add('hidden');
        }
    }

    // ══════════════════ Actions ══════════════════

    async function doInstall() {
        if (isOperationRunning) return;

        isOperationRunning = true;
        renderActions();
        showProgress('Начало установки...', 0);
        startProgressPolling();

        try {
            const result = await API.post('/api/zapret/install', {});
            if (result.in_progress) {
                Toast.info('Установка запущена. Ожидайте...');
                // Продолжаем polling прогресса
            } else if (result.ok) {
                Toast.success(result.message || 'zapret2 установлен');
                hideProgress();
                await loadData();
            } else {
                Toast.error(result.message || 'Ошибка установки');
                hideProgress();
            }
        } catch (err) {
            Toast.error('Ошибка: ' + err.message);
            hideProgress();
        } finally {
            isOperationRunning = false;
            renderActions();
        }
    }

    async function doUpdate() {
        if (isOperationRunning) return;

        isOperationRunning = true;
        renderActions();
        showProgress('Начало обновления...', 0);
        startProgressPolling();

        try {
            const result = await API.post('/api/zapret/update', {});
            if (result.in_progress) {
                Toast.info('Обновление запущено. Ожидайте...');
            } else if (result.ok) {
                Toast.success(result.message || 'zapret2 обновлён');
                hideProgress();
                await loadData();
            } else {
                Toast.error(result.message || 'Ошибка обновления');
                hideProgress();
            }
        } catch (err) {
            Toast.error('Ошибка: ' + err.message);
            hideProgress();
        } finally {
            isOperationRunning = false;
            renderActions();
        }
    }

    async function showUninstallPlan() {
        if (isOperationRunning) return;

        try {
            const plan = await API.get('/api/zapret/uninstall-plan');

            const listEl = document.getElementById('zm-uninstall-list');
            const warningsEl = document.getElementById('zm-uninstall-warnings');

            if (listEl) {
                if (plan.items && plan.items.length > 0) {
                    listEl.innerHTML = plan.items.map(item => `
                        <div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px;
                                    background: var(--bg-input); border-radius: var(--radius-sm);
                                    margin-bottom: 4px; font-size: 12px;">
                            <span style="color: ${item.type === 'dir' ? 'var(--warning)' : 'var(--text-secondary)'};">\n                                ${item.type === 'dir' ? '📁' : '📄'}
                            </span>
                            <div style="flex: 1; min-width: 0;">
                                <div style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px;
                                            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                    ${escapeHtml(item.path)}
                                </div>
                                <div style="color: var(--text-muted); font-size: 11px;">
                                    ${escapeHtml(item.description)}
                                </div>
                            </div>
                        </div>
                    `).join('');
                } else {
                    listEl.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 16px;">Нечего удалять</div>';
                }
            }

            if (warningsEl && plan.warnings && plan.warnings.length > 0) {
                warningsEl.innerHTML = plan.warnings.map(w => `
                    <div style="display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--warning); margin-bottom: 4px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        ${escapeHtml(w)}
                    </div>
                `).join('');
            }

            // Показываем модал
            const modal = document.getElementById('zm-uninstall-modal');
            if (modal) modal.classList.remove('hidden');

        } catch (err) {
            Toast.error('Ошибка получения плана: ' + err.message);
        }
    }

    async function confirmUninstall() {
        closeUninstallModal();

        if (isOperationRunning) return;

        isOperationRunning = true;
        renderActions();
        showProgress('Удаление zapret2...', 0);
        startProgressPolling();

        try {
            const result = await API.post('/api/zapret/uninstall', { confirm: true });
            if (result.in_progress) {
                Toast.info('Удаление запущено. Ожидайте...');
            } else if (result.ok) {
                Toast.success(result.message || 'zapret2 удалён');
                hideProgress();
                await loadData();
            } else {
                Toast.error(result.message || 'Ошибка удаления');
                hideProgress();
            }
        } catch (err) {
            Toast.error('Ошибка: ' + err.message);
            hideProgress();
        } finally {
            isOperationRunning = false;
            renderActions();
        }
    }

    function closeUninstallModal(event) {
        if (event && event.target !== event.currentTarget) return;
        const modal = document.getElementById('zm-uninstall-modal');
        if (modal) modal.classList.add('hidden');
    }

    async function refresh() {
        const btn = document.getElementById('zm-btn-refresh');
        if (btn) {
            btn.disabled = true;
            const origHtml = btn.innerHTML;
            btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;"></span> Проверка...';

            try {
                // Сбрасываем кэш remote-версии
                data = await API.get('/api/zapret?force=1');
                if (data.ok) {
                    renderData();
                    Toast.success('Данные обновлены');
                }
            } catch (err) {
                Toast.error('Ошибка: ' + err.message);
            } finally {
                btn.innerHTML = origHtml;
                btn.disabled = false;
            }
        } else {
            await loadData();
        }
    }

    // ══════════════════ Progress ══════════════════

    function showProgress(status, progress, titleText) {
        const card = document.getElementById('zm-progress-card');
        const bar = document.getElementById('zm-progress-bar');
        const text = document.getElementById('zm-progress-text');
        const title = document.getElementById('zm-progress-title');

        if (card) card.classList.remove('hidden');
        if (bar) bar.style.width = Math.max(0, Math.min(100, progress)) + '%';
        if (text) text.textContent = status || 'Обработка...';
        if (title) {
            if (progress >= 100) {
                title.textContent = 'Завершено';
            } else {
                title.textContent = titleText || 'Выполняется операция...';
            }
        }
    }

    function hideProgress() {
        const card = document.getElementById('zm-progress-card');
        if (card) card.classList.add('hidden');
        stopProgressPolling();
    }

    function startProgressPolling() {
        stopProgressPolling();
        progressTimer = setInterval(async () => {
            try {
                const prog = await API.get('/api/zapret/progress');
                if (prog.ok) {
                    if (prog.in_progress) {
                        showProgress(prog.status, prog.progress);
                    } else {
                        hideProgress();
                        await loadData();
                        isOperationRunning = false;
                        renderActions();
                    }
                }
            } catch {
                // Тихо игнорируем
            }
        }, 1500);
    }

    function stopProgressPolling() {
        if (progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
        }
    }

    function startGuiProgressPolling() {
        stopGuiProgressPolling();
        guiProgressTimer = setInterval(async () => {
            try {
                const prog = await API.get('/api/gui/progress');
                if (prog.ok) {
                    if (prog.in_progress) {
                        showProgress(prog.status, prog.progress, 'Обновление zapret-gui...');
                    } else {
                        stopGuiProgressPolling();
                        if (guiUpdateRunning) {
                            guiUpdateRunning = false;
                            showProgress('Обновление завершено!', 100, 'Обновление zapret-gui...');
                            setTimeout(() => {
                                hideProgress();
                                showGuiReloadPrompt();
                            }, 1200);
                        }
                    }
                }
            } catch {
                // Тихо игнорируем
            }
        }, 1500);
    }

    function stopGuiProgressPolling() {
        if (guiProgressTimer) {
            clearInterval(guiProgressTimer);
            guiProgressTimer = null;
        }
    }

    // ══════════════════ Helpers ══════════════════

    function formatDate(isoStr) {
        try {
            const d = new Date(isoStr);
            return d.toLocaleDateString('ru-RU', {
                year: 'numeric', month: 'short', day: 'numeric'
            });
        } catch {
            return '';
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function setError(msg) {
        const instVer = document.getElementById('zm-installed-version');
        if (instVer) {
            instVer.textContent = 'Ошибка';
            instVer.style.color = 'var(--error)';
        }
        const instDetail = document.getElementById('zm-installed-detail');
        if (instDetail) instDetail.textContent = msg;
    }

    // ══════════════════ Poll ══════════════════

    function startPoll() {
        pollTimer = setInterval(loadData, 30000); // Обновление каждые 30 сек
    }

    // ══════════════════ GUI Update ══════════════════

    function showGuiUpdateBanner(info) {
        const banner = document.getElementById('gui-update-banner');
        if (!banner) return;
        banner.classList.remove('hidden');
        const ver = document.getElementById('gui-update-version');
        if (ver) ver.textContent = info.latest_version || '?';
    }

    function showGuiReloadPrompt() {
        const banner = document.getElementById('gui-update-banner');
        if (banner) {
            banner.classList.remove('hidden');
            banner.innerHTML = `
                <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                    <div>
                        <span style="font-weight:600; color:var(--success);">zapret-gui обновлён!</span>
                        <span style="color:var(--text-secondary); font-size:13px; margin-left:8px;">
                            Перезагрузите страницу для применения изменений
                        </span>
                    </div>
                    <button class="btn btn-success btn-sm" onclick="location.reload()">
                        Перезагрузить страницу
                    </button>
                </div>
            `;
        }
        Toast.success('GUI обновлён! Нажмите F5 или кнопку "Перезагрузить страницу".');
    }

    async function doGuiUpdate() {
        if (isOperationRunning || guiUpdateRunning) return;

        guiUpdateRunning = true;
        showProgress('Запуск обновления GUI...', 0, 'Обновление zapret-gui...');
        startGuiProgressPolling();

        try {
            const result = await API.post('/api/gui/update', {});

            if (result.in_progress) {
                Toast.info('Обновление GUI запущено. Следите за прогрессом...');
                // Продолжаем polling — он сам завершит процесс
            } else if (result.ok) {
                stopGuiProgressPolling();
                guiUpdateRunning = false;
                showProgress('Обновление завершено!', 100, 'Обновление zapret-gui...');
                setTimeout(() => {
                    hideProgress();
                    showGuiReloadPrompt();
                }, 1200);
            } else {
                stopGuiProgressPolling();
                guiUpdateRunning = false;
                hideProgress();
                Toast.error(result.message || 'Ошибка обновления GUI');
            }
        } catch (err) {
            stopGuiProgressPolling();
            guiUpdateRunning = false;
            hideProgress();
            Toast.error('Ошибка: ' + err.message);
        }
    }

    // ══════════════════ Destroy ══════════════════

    function destroy() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
        stopProgressPolling();
        stopGuiProgressPolling();
        data = null;
        isOperationRunning = false;
        guiUpdateRunning = false;
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        refresh,
        doInstall,
        doUpdate,
        showUninstallPlan,
        confirmUninstall,
        closeUninstallModal,
        updateGui: doGuiUpdate,
    };
})();
