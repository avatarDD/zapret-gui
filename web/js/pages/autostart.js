/**
 * autostart.js — Страница автозапуска.
 *
 * Возможности:
 *   - Включение/выключение автозапуска (toggle)
 *   - Просмотр текущего статуса
 *   - Превью и просмотр init.d-скрипта
 *   - Пересоздание скрипта при изменении стратегии
 */

const AutostartPage = (() => {
    // ══════════════════ State ══════════════════

    let status = null;
    let pollTimer = null;
    let isLoading = false;

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Автозапуск</h1>
                    <p class="page-description">Автоматический запуск nfqws2 при загрузке роутера</p>
                </div>
            </div>

            <!-- Основная карточка -->
            <div class="card" id="autostart-main-card" style="padding: 20px;">
                <div class="autostart-card">
                    <div class="autostart-info">
                        <div class="autostart-icon disabled" id="autostart-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                                <path d="M18.36 6.64a9 9 0 1 1-12.73 0"/>
                                <line x1="12" y1="2" x2="12" y2="12"/>
                            </svg>
                        </div>
                        <div class="autostart-details">
                            <div class="autostart-title" id="autostart-title">Автозапуск отключён</div>
                            <div class="autostart-desc" id="autostart-desc">Загрузка...</div>
                        </div>
                    </div>
                    <div class="autostart-actions">
                        <label class="toggle-switch" id="autostart-toggle" title="Включить/выключить автозапуск">
                            <input type="checkbox" id="autostart-checkbox" onchange="AutostartPage.toggleAutostart(this.checked)">
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
            </div>

            <!-- Информационные карточки -->
            <div class="status-grid" style="margin-top: 16px;" id="autostart-info-grid">
                <div class="status-card">
                    <div class="status-card-label">Стратегия</div>
                    <div class="status-card-value" id="autostart-strategy" style="font-size: 14px;">—</div>
                </div>
                <div class="status-card">
                    <div class="status-card-label">Скрипт</div>
                    <div class="status-card-value" id="autostart-script-status" style="font-size: 14px;">—</div>
                </div>
                <div class="status-card">
                    <div class="status-card-label">Путь</div>
                    <div class="status-card-value" id="autostart-path" style="font-size: 11px; font-family: var(--font-mono);">/opt/etc/init.d/S99zapret</div>
                </div>
                <div class="status-card">
                    <div class="status-card-label">Init.d</div>
                    <div class="status-card-value" id="autostart-initd-status" style="font-size: 14px;">—</div>
                </div>
            </div>

            <!-- Действия -->
            <div class="card" style="margin-top: 16px; padding: 16px 20px;">
                <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;">
                    <div>
                        <div style="font-size: 14px; font-weight: 500; color: var(--text-primary); margin-bottom: 2px;">Управление скриптом</div>
                        <div style="font-size: 12px; color: var(--text-secondary);">Пересоздать скрипт или просмотреть его содержимое</div>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <button class="btn btn-ghost btn-sm" onclick="AutostartPage.regenerate()" id="btn-regenerate">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="23 4 23 10 17 10"/>
                                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                            </svg>
                            Пересоздать
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="AutostartPage.showScript()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                            </svg>
                            Просмотр скрипта
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="AutostartPage.showPreview()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                            </svg>
                            Превью нового
                        </button>
                    </div>
                </div>
            </div>

            <!-- Подсказка -->
            <div class="card" style="margin-top: 16px; padding: 16px 20px; border-left: 3px solid var(--info);">
                <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
                    <strong style="color: var(--info);">Как это работает</strong><br>
                    Автозапуск создаёт скрипт <code style="color: var(--accent); background: rgba(91,158,244,0.1); padding: 1px 5px; border-radius: 3px; font-size: 12px;">/opt/etc/init.d/S99zapret</code>,
                    который Entware выполняет при загрузке роутера. Скрипт запускает nfqws2 с текущей стратегией
                    и применяет правила firewall.<br>
                    При смене стратегии нужно <strong>пересоздать скрипт</strong>, чтобы обновить параметры.
                </div>
            </div>

            <!-- Модальное окно просмотра скрипта -->
            <div class="modal-backdrop hidden" id="script-modal" onclick="AutostartPage.closeModal(event)">
                <div class="modal-content modal-lg" onclick="event.stopPropagation()">
                    <div class="modal-header">
                        <h3 id="script-modal-title">Скрипт автозапуска</h3>
                        <button class="btn btn-ghost btn-sm" onclick="AutostartPage.closeModal()" style="margin-left:auto;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body" style="padding: 0;">
                        <div style="position: relative;">
                            <button class="btn btn-ghost btn-sm" onclick="AutostartPage.copyScript()"
                                    style="position: absolute; top: 8px; right: 8px; z-index: 2;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                </svg>
                                Копировать
                            </button>
                            <pre id="script-modal-content" style="
                                margin: 0;
                                padding: 16px;
                                background: var(--bg-input);
                                color: var(--text-primary);
                                font-family: var(--font-mono);
                                font-size: 11px;
                                line-height: 1.6;
                                max-height: 500px;
                                overflow: auto;
                                white-space: pre;
                                border-radius: 0 0 var(--radius-lg) var(--radius-lg);
                            "></pre>
                        </div>
                    </div>
                </div>
            </div>
        `;

        loadStatus();
        startPoll();
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadStatus() {
        try {
            const data = await API.get('/api/autostart');
            if (data.ok !== false) {
                status = data;
                renderStatus();
            }
        } catch (err) {
            console.error('Failed to load autostart status:', err);
        }
    }

    function renderStatus() {
        if (!status) return;

        const enabled = status.enabled;
        const scriptExists = status.script_exists;
        const initDirExists = status.init_dir_exists;

        // Toggle
        const checkbox = document.getElementById('autostart-checkbox');
        if (checkbox) checkbox.checked = enabled;

        // Icon
        const icon = document.getElementById('autostart-icon');
        if (icon) {
            icon.className = 'autostart-icon ' + (enabled ? 'enabled' : 'disabled');
        }

        // Title
        const title = document.getElementById('autostart-title');
        if (title) {
            title.textContent = enabled ? 'Автозапуск включён' : 'Автозапуск отключён';
            title.style.color = enabled ? 'var(--success)' : 'var(--text-primary)';
        }

        // Description
        const desc = document.getElementById('autostart-desc');
        if (desc) {
            if (enabled) {
                desc.textContent = 'nfqws2 будет запущен автоматически при загрузке роутера';
            } else {
                desc.textContent = 'Включите для автоматического запуска при загрузке';
            }
        }

        // Strategy
        const strategyEl = document.getElementById('autostart-strategy');
        if (strategyEl) {
            const name = status.strategy_name || 'Не выбрана';
            strategyEl.textContent = name;
            strategyEl.style.color = status.strategy_id ? 'var(--accent)' : 'var(--text-muted)';
        }

        // Script status
        const scriptEl = document.getElementById('autostart-script-status');
        if (scriptEl) {
            if (scriptExists) {
                scriptEl.innerHTML = '<span style="color: var(--success);">Установлен</span>';
            } else {
                scriptEl.innerHTML = '<span style="color: var(--text-muted);">Не установлен</span>';
            }
        }

        // Init.d status
        const initdEl = document.getElementById('autostart-initd-status');
        if (initdEl) {
            if (initDirExists) {
                initdEl.innerHTML = '<span style="color: var(--success);">Доступна</span>';
            } else {
                initdEl.innerHTML = '<span style="color: var(--error);">Не найдена</span>';
            }
        }

        // Path
        const pathEl = document.getElementById('autostart-path');
        if (pathEl) {
            pathEl.textContent = status.script_path || '/opt/etc/init.d/S99zapret';
        }

        // Regenerate button
        const regenBtn = document.getElementById('btn-regenerate');
        if (regenBtn) {
            regenBtn.disabled = !enabled;
        }
    }

    // ══════════════════ Actions ══════════════════

    async function toggleAutostart(checked) {
        if (isLoading) return;
        isLoading = true;

        const checkbox = document.getElementById('autostart-checkbox');

        try {
            let result;
            if (checked) {
                result = await API.post('/api/autostart/enable');
            } else {
                result = await API.post('/api/autostart/disable');
            }

            if (result.ok) {
                Toast.show(result.message, 'success');
                await loadStatus();
            } else {
                Toast.show(result.message || 'Ошибка', 'error');
                // Откатываем checkbox
                if (checkbox) checkbox.checked = !checked;
            }
        } catch (err) {
            Toast.show('Ошибка: ' + err.message, 'error');
            if (checkbox) checkbox.checked = !checked;
        } finally {
            isLoading = false;
        }
    }

    async function regenerate() {
        if (isLoading) return;
        isLoading = true;

        try {
            const result = await API.post('/api/autostart/regenerate');

            if (result.ok) {
                Toast.show(result.message, 'success');
                await loadStatus();
            } else {
                Toast.show(result.message || 'Ошибка пересоздания', 'error');
            }
        } catch (err) {
            Toast.show('Ошибка: ' + err.message, 'error');
        } finally {
            isLoading = false;
        }
    }

    async function showScript() {
        try {
            const data = await API.get('/api/autostart/script');

            const modal = document.getElementById('script-modal');
            const title = document.getElementById('script-modal-title');
            const content = document.getElementById('script-modal-content');

            if (title) title.textContent = 'Установленный скрипт';

            if (data.exists && data.script) {
                if (content) content.textContent = data.script;
            } else {
                if (content) content.textContent = '# Скрипт не установлен';
            }

            if (modal) modal.classList.remove('hidden');
        } catch (err) {
            Toast.show('Ошибка загрузки: ' + err.message, 'error');
        }
    }

    async function showPreview() {
        try {
            const data = await API.get('/api/autostart/preview');

            const modal = document.getElementById('script-modal');
            const title = document.getElementById('script-modal-title');
            const content = document.getElementById('script-modal-content');

            if (title) title.textContent = 'Превью скрипта (будет сгенерирован)';
            if (content) content.textContent = data.script || '# Ошибка генерации';

            if (modal) modal.classList.remove('hidden');
        } catch (err) {
            Toast.show('Ошибка: ' + err.message, 'error');
        }
    }

    async function copyScript() {
        const content = document.getElementById('script-modal-content');
        if (!content) return;

        try {
            await navigator.clipboard.writeText(content.textContent);
            Toast.show('Скрипт скопирован', 'success');
        } catch (err) {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = content.textContent;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                Toast.show('Скрипт скопирован', 'success');
            } catch (e2) {
                Toast.show('Не удалось скопировать', 'error');
            }
            document.body.removeChild(ta);
        }
    }

    function closeModal(event) {
        if (event && event.target !== event.currentTarget) return;
        const modal = document.getElementById('script-modal');
        if (modal) modal.classList.add('hidden');
    }

    // ══════════════════ Poll ══════════════════

    function startPoll() {
        pollTimer = setInterval(loadStatus, 15000);
    }

    // ══════════════════ Destroy ══════════════════

    function destroy() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
        status = null;
        isLoading = false;
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        toggleAutostart,
        regenerate,
        showScript,
        showPreview,
        copyScript,
        closeModal,
    };
})();