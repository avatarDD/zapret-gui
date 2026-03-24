/**
 * hosts.js — Страница управления файлом /etc/hosts.
 *
 * Функции: просмотр записей (системные + GUI), добавление,
 * удаление, блокировка доменов, пресеты, raw-редактор, бэкапы.
 */

const HostsPage = (() => {

    // Состояние
    let entries = [];
    let stats = {};
    let presets = [];
    let activeTab = 'entries';  // entries | presets | raw
    let rawOriginal = '';
    let rawHasChanges = false;

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                            <line x1="6" y1="6" x2="6.01" y2="6"/>
                            <line x1="6" y1="18" x2="6.01" y2="18"/>
                        </svg>
                        Hosts
                    </h1>
                    <p class="page-description">Управление файлом /etc/hosts — DNS-перенаправления и блокировка доменов</p>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-ghost" onclick="HostsPage.doBackup()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                            <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                        </svg>
                        Бэкап
                    </button>
                    <button class="btn btn-ghost" onclick="HostsPage.showRestoreModal()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="1 4 1 10 7 10"/>
                            <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                        </svg>
                        Восстановить
                    </button>
                </div>
            </div>

            <!-- Статистика -->
            <div class="status-grid" id="hosts-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <!-- Табы -->
            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="hosts-tabs">
                    <button class="lists-tab ${activeTab === 'entries' ? 'active' : ''}"
                            data-tab="entries" onclick="HostsPage.switchTab('entries')">
                        <span class="lists-tab-name">Записи</span>
                        <span class="lists-tab-count" id="hosts-tab-count-entries">—</span>
                    </button>
                    <button class="lists-tab ${activeTab === 'presets' ? 'active' : ''}"
                            data-tab="presets" onclick="HostsPage.switchTab('presets')">
                        <span class="lists-tab-name">Пресеты</span>
                    </button>
                    <button class="lists-tab ${activeTab === 'raw' ? 'active' : ''}"
                            data-tab="raw" onclick="HostsPage.switchTab('raw')">
                        <span class="lists-tab-name">Raw-редактор</span>
                    </button>
                </div>

                <!-- Содержимое вкладок -->
                <div id="hosts-tab-content" class="lists-content">
                    <div class="text-muted" style="text-align:center; padding:32px;">
                        <div class="spinner" style="margin:0 auto 12px;"></div>
                        Загрузка...
                    </div>
                </div>
            </div>

            <!-- Подсказка -->
            <div class="card" style="border-left: 3px solid var(--info);">
                <div class="card-title" style="font-size:13px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" style="vertical-align: -2px; color: var(--info);">
                        <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/>
                        <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                    Как работает /etc/hosts
                </div>
                <div style="font-size:12px; color:var(--text-secondary); line-height:1.7;">
                    Файл <code style="background:var(--bg-input); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">/etc/hosts</code>
                    переопределяет DNS для указанных доменов на уровне ОС.<br>
                    <strong>0.0.0.0 → домен</strong> — блокирует домен (реклама, трекеры).<br>
                    <strong>IP → домен</strong> — перенаправляет домен на конкретный IP (обход DNS-блокировок).<br>
                    GUI управляет только записями между маркерами <code style="background:var(--bg-input); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">ZAPRET-GUI BEGIN/END</code>. Системные записи не затрагиваются.
                </div>
            </div>

            <!-- Модал: восстановление из бэкапа -->
            <div id="hosts-restore-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Восстановить из бэкапа</h3>
                        <button class="modal-close" onclick="HostsPage.closeRestoreModal()">&times;</button>
                    </div>
                    <div class="modal-body" id="hosts-restore-body">
                        <div class="text-muted" style="text-align:center; padding:24px;">Загрузка бэкапов...</div>
                    </div>
                </div>
            </div>

            <!-- Модал: применение пресета с редактированием -->
            <div id="hosts-preset-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title" id="hosts-preset-modal-title">Применить пресет</h3>
                        <button class="modal-close" onclick="HostsPage.closePresetModal()">&times;</button>
                    </div>
                    <div class="modal-body" id="hosts-preset-modal-body">
                    </div>
                </div>
            </div>
        `;

        loadData();
    }

    function destroy() {
        entries = [];
        stats = {};
        presets = [];
        rawOriginal = '';
        rawHasChanges = false;
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadData() {
        try {
            const [statsRes, customRes, presetsRes] = await Promise.all([
                API.get('/api/hosts/stats'),
                API.get('/api/hosts/custom'),
                API.get('/api/hosts/presets'),
            ]);

            stats = statsRes.stats || {};
            entries = customRes.entries || [];
            presets = presetsRes.presets || [];

            renderStats();
            renderTabContent();
        } catch (err) {
            Toast.show('Ошибка загрузки: ' + err.message, 'error');
            const content = document.getElementById('hosts-tab-content');
            if (content) {
                content.innerHTML = `<div style="text-align:center; padding:32px; color:var(--error);">
                    Ошибка загрузки данных: ${err.message}</div>`;
            }
        }
    }

    async function refreshData() {
        try {
            const [statsRes, customRes] = await Promise.all([
                API.get('/api/hosts/stats'),
                API.get('/api/hosts/custom'),
            ]);
            stats = statsRes.stats || {};
            entries = customRes.entries || [];
            renderStats();
            if (activeTab === 'entries') renderEntriesTab();
        } catch (err) {
            Toast.show('Ошибка обновления: ' + err.message, 'error');
        }
    }

    // ══════════════════ Stats ══════════════════

    function renderStats() {
        const grid = document.getElementById('hosts-stats-grid');
        if (!grid) return;

        grid.innerHTML = `
            <div class="status-card">
                <div class="status-card-value">${stats.total || 0}</div>
                <div class="status-card-label">Всего записей</div>
            </div>
            <div class="status-card">
                <div class="status-card-value">${stats.system || 0}</div>
                <div class="status-card-label">Системных</div>
            </div>
            <div class="status-card">
                <div class="status-card-value" style="color: var(--accent);">${stats.custom || 0}</div>
                <div class="status-card-label">GUI-записей</div>
            </div>
            <div class="status-card">
                <div class="status-card-value" style="color: var(--warning);">${stats.blocked || 0}</div>
                <div class="status-card-label">Заблокировано</div>
            </div>
            <div class="status-card">
                <div class="status-card-value" style="color: var(--success);">${stats.redirected || 0}</div>
                <div class="status-card-label">Перенаправлено</div>
            </div>
        `;
    }

    // ══════════════════ Tabs ══════════════════

    function switchTab(tab) {
        activeTab = tab;

        // Обновляем кнопки табов
        document.querySelectorAll('#hosts-tabs .lists-tab').forEach(el => {
            el.classList.toggle('active', el.dataset.tab === tab);
        });

        renderTabContent();
    }

    function renderTabContent() {
        const content = document.getElementById('hosts-tab-content');
        if (!content) return;

        switch (activeTab) {
            case 'entries':
                renderEntriesTab();
                break;
            case 'presets':
                renderPresetsTab();
                break;
            case 'raw':
                renderRawTab();
                break;
        }
    }

    // ══════════════════ Entries Tab ══════════════════

    function renderEntriesTab() {
        const content = document.getElementById('hosts-tab-content');
        if (!content) return;

        const countEl = document.getElementById('hosts-tab-count-entries');
        if (countEl) countEl.textContent = entries.length;

        let tableHtml = '';
        if (entries.length === 0) {
            tableHtml = `
                <div style="text-align:center; padding:40px 20px; color:var(--text-muted);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                         width="40" height="40" style="margin-bottom:12px; opacity:0.5;">
                        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                        <line x1="6" y1="6" x2="6.01" y2="6"/>
                        <line x1="6" y1="18" x2="6.01" y2="18"/>
                    </svg>
                    <div style="font-size:14px; font-weight:500; margin-bottom:4px;">Нет GUI-записей</div>
                    <div style="font-size:12px;">Добавьте запись вручную, заблокируйте домен или примените пресет</div>
                </div>
            `;
        } else {
            tableHtml = '<div class="blob-table">';
            tableHtml += `
                <div class="blob-table-header">
                    <div style="flex:1.2;">IP-адрес</div>
                    <div style="flex:2;">Домен</div>
                    <div style="flex:0.8; text-align:center;">Тип</div>
                    <div style="flex:0.5; text-align:right;">Действия</div>
                </div>
            `;

            entries.forEach(e => {
                const isBlock = e.ip === '0.0.0.0';
                const typeBadge = isBlock
                    ? '<span class="blob-badge" style="background:rgba(239,68,68,0.15); color:var(--error);">Блок</span>'
                    : '<span class="blob-badge" style="background:rgba(34,197,94,0.15); color:var(--success);">Redirect</span>';

                tableHtml += `
                    <div class="blob-table-row">
                        <div style="flex:1.2; font-family:var(--font-mono); font-size:12px; color:${isBlock ? 'var(--error)' : 'var(--accent)'};">
                            ${escapeHtml(e.ip)}
                        </div>
                        <div style="flex:2; font-family:var(--font-mono); font-size:12px;">
                            ${escapeHtml(e.domain)}
                        </div>
                        <div style="flex:0.8; text-align:center;">
                            ${typeBadge}
                        </div>
                        <div style="flex:0.5; text-align:right;">
                            <button class="btn btn-ghost btn-sm" onclick="HostsPage.removeEntry('${escapeAttr(e.domain)}')"
                                    title="Удалить" style="color:var(--error); padding:4px 6px;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
            });

            tableHtml += '</div>';
        }

        content.innerHTML = `
            <div class="lists-toolbar">
                <div class="lists-toolbar-left">
                    <span style="font-size:12px; color:var(--text-muted);">
                        GUI-записи между маркерами ZAPRET-GUI
                    </span>
                </div>
                <div class="lists-toolbar-right">
                    <button class="btn btn-ghost btn-sm" onclick="HostsPage.refreshData()" title="Обновить">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="23 4 23 10 17 10"/>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                    </button>
                    ${entries.length > 0 ? `
                        <button class="btn btn-danger btn-sm" onclick="HostsPage.clearAll()" title="Удалить все GUI-записи">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                            Очистить всё
                        </button>
                    ` : ''}
                </div>
            </div>

            ${tableHtml}

            <!-- Добавление записи -->
            <div class="lists-add-section">
                <div class="lists-add-header">
                    <span class="form-label" style="margin:0;">Добавить запись</span>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end;">
                    <div style="flex:1; min-width:140px;">
                        <label class="form-label" style="font-size:11px; margin-bottom:4px;">IP-адрес</label>
                        <input type="text" class="form-input" id="hosts-add-ip"
                               placeholder="0.0.0.0" value="0.0.0.0"
                               spellcheck="false" style="font-family:var(--font-mono); font-size:13px;">
                    </div>
                    <div style="flex:2; min-width:200px;">
                        <label class="form-label" style="font-size:11px; margin-bottom:4px;">Домен</label>
                        <input type="text" class="form-input" id="hosts-add-domain"
                               placeholder="example.com"
                               spellcheck="false" style="font-family:var(--font-mono); font-size:13px;"
                               onkeydown="if(event.key==='Enter') HostsPage.addEntry()">
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="HostsPage.addEntry()" style="height:38px; white-space:nowrap;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                        </svg>
                        Добавить
                    </button>
                </div>
                <div class="form-hint" style="margin-top:6px;">
                    <strong>0.0.0.0</strong> — блокировка домена &nbsp;|&nbsp;
                    Конкретный <strong>IP</strong> — перенаправление (обход блокировок)
                </div>
            </div>

            <!-- Быстрая блокировка -->
            <div class="lists-add-section" style="border-top:1px solid var(--border);">
                <div class="lists-add-header">
                    <span class="form-label" style="margin:0;">Быстрая блокировка</span>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end;">
                    <div style="flex:1; min-width:250px;">
                        <input type="text" class="form-input" id="hosts-block-input"
                               placeholder="Домены через запятую: tracker1.com, ads.site.ru"
                               spellcheck="false" style="font-family:var(--font-mono); font-size:13px;"
                               onkeydown="if(event.key==='Enter') HostsPage.quickBlock()">
                    </div>
                    <button class="btn btn-ghost btn-sm" onclick="HostsPage.quickBlock()" style="height:38px; white-space:nowrap; color:var(--warning);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                        </svg>
                        Заблокировать
                    </button>
                </div>
                <div class="form-hint" style="margin-top:6px;">
                    Все домены будут направлены на 0.0.0.0 (полная блокировка)
                </div>
            </div>
        `;
    }

    // ══════════════════ Presets Tab ══════════════════

    function renderPresetsTab() {
        const content = document.getElementById('hosts-tab-content');
        if (!content) return;

        if (presets.length === 0) {
            content.innerHTML = `
                <div style="text-align:center; padding:40px; color:var(--text-muted);">
                    Пресеты не найдены
                </div>
            `;
            return;
        }

        let html = '<div style="padding:16px; display:flex; flex-direction:column; gap:12px;">';

        presets.forEach(p => {
            const iconColor = p.id === 'block_ads' || p.id === 'block_telemetry'
                ? 'var(--warning)'
                : 'var(--accent)';

            html += `
                <div style="
                    background:var(--bg-secondary);
                    border:1px solid var(--border);
                    border-radius:var(--radius);
                    padding:16px;
                    display:flex;
                    justify-content:space-between;
                    align-items:center;
                    gap:16px;
                    flex-wrap:wrap;
                ">
                    <div style="flex:1; min-width:200px;">
                        <div style="font-size:14px; font-weight:600; color:var(--text-primary); margin-bottom:4px; display:flex; align-items:center; gap:8px;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2" width="16" height="16">
                                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                                <line x1="6" y1="6" x2="6.01" y2="6"/>
                                <line x1="6" y1="18" x2="6.01" y2="18"/>
                            </svg>
                            ${escapeHtml(p.name)}
                        </div>
                        <div style="font-size:12px; color:var(--text-secondary); margin-bottom:6px;">
                            ${escapeHtml(p.description)}
                        </div>
                        <div style="font-size:11px; color:var(--text-muted);">
                            ${p.count} записей
                        </div>
                    </div>
                    <div style="display:flex; gap:8px;">
                        <button class="btn btn-ghost btn-sm" onclick="HostsPage.openPresetModal('${escapeAttr(p.id)}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                            Просмотр
                        </button>
                        <button class="btn btn-primary btn-sm" onclick="HostsPage.applyPreset('${escapeAttr(p.id)}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="20 6 9 17 4 12"/>
                            </svg>
                            Применить
                        </button>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        content.innerHTML = html;
    }

    // ══════════════════ Raw Tab ══════════════════

    async function renderRawTab() {
        const content = document.getElementById('hosts-tab-content');
        if (!content) return;

        content.innerHTML = `
            <div class="lists-toolbar">
                <div class="lists-toolbar-left">
                    <span style="font-size:12px; color:var(--text-muted);">
                        Полное содержимое /etc/hosts
                    </span>
                    <span class="lists-unsaved" id="hosts-raw-unsaved" style="display:none;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                        Несохранённые изменения
                    </span>
                </div>
                <div class="lists-toolbar-right">
                    <button class="btn btn-ghost btn-sm" onclick="HostsPage.refreshRaw()" title="Обновить">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="23 4 23 10 17 10"/>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                    </button>
                    <button class="btn btn-primary btn-sm" id="hosts-raw-save-btn" onclick="HostsPage.saveRaw()" disabled>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                            <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                        </svg>
                        Сохранить
                    </button>
                </div>
            </div>
            <textarea class="lists-editor" id="hosts-raw-editor"
                      placeholder="Загрузка содержимого /etc/hosts..."
                      spellcheck="false"
                      style="min-height:350px;"></textarea>
            <div style="padding:8px 12px; font-size:11px; color:var(--text-muted); border-top:1px solid var(--border);">
                ⚠️ Будьте осторожны при ручном редактировании — не удаляйте системные записи (localhost и т.д.)
            </div>
        `;

        // Загружаем содержимое
        try {
            const res = await API.get('/api/hosts/raw');
            rawOriginal = res.text || '';
            rawHasChanges = false;

            const editor = document.getElementById('hosts-raw-editor');
            if (editor) {
                editor.value = rawOriginal;
                editor.addEventListener('input', onRawInput);
            }
        } catch (err) {
            Toast.show('Ошибка загрузки raw: ' + err.message, 'error');
        }
    }

    function onRawInput() {
        const editor = document.getElementById('hosts-raw-editor');
        if (!editor) return;

        rawHasChanges = editor.value !== rawOriginal;

        const unsaved = document.getElementById('hosts-raw-unsaved');
        if (unsaved) unsaved.style.display = rawHasChanges ? '' : 'none';

        const saveBtn = document.getElementById('hosts-raw-save-btn');
        if (saveBtn) saveBtn.disabled = !rawHasChanges;
    }

    // ══════════════════ Actions ══════════════════

    async function addEntry() {
        const ipInput = document.getElementById('hosts-add-ip');
        const domainInput = document.getElementById('hosts-add-domain');
        if (!ipInput || !domainInput) return;

        const ip = ipInput.value.trim();
        const domain = domainInput.value.trim();

        if (!ip) { Toast.show('Укажите IP-адрес', 'warning'); ipInput.focus(); return; }
        if (!domain) { Toast.show('Укажите домен', 'warning'); domainInput.focus(); return; }

        try {
            const res = await API.post('/api/hosts/add', { ip, domain });
            Toast.show(res.message || 'Запись добавлена', 'success');
            domainInput.value = '';
            await refreshData();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function removeEntry(domain) {
        if (!confirm(`Удалить запись для ${domain}?`)) return;

        try {
            const res = await API.post('/api/hosts/remove', { domain });
            Toast.show(res.message || 'Запись удалена', 'success');
            await refreshData();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function quickBlock() {
        const input = document.getElementById('hosts-block-input');
        if (!input) return;

        const text = input.value.trim();
        if (!text) { Toast.show('Введите домены для блокировки', 'warning'); input.focus(); return; }

        const domains = text.split(/[\s,;]+/).map(d => d.trim()).filter(Boolean);
        if (domains.length === 0) { Toast.show('Не удалось распознать домены', 'warning'); return; }

        try {
            const res = await API.post('/api/hosts/block', { domains });
            Toast.show(res.message || `Заблокировано: ${res.count}`, 'success');
            input.value = '';
            await refreshData();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function clearAll() {
        if (!confirm('Удалить ВСЕ GUI-записи из /etc/hosts?\nСистемные записи не будут затронуты.')) return;

        try {
            const res = await API.post('/api/hosts/clear');
            Toast.show(res.message || 'Все GUI-записи удалены', 'success');
            await refreshData();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function applyPreset(presetId) {
        const preset = presets.find(p => p.id === presetId);
        if (!preset) return;

        if (!confirm(`Применить пресет "${preset.name}"?\nБудет добавлено ${preset.count} записей.`)) return;

        try {
            const res = await API.post('/api/hosts/preset', { name: presetId });
            Toast.show(res.message || 'Пресет применён', 'success');
            await refreshData();
            switchTab('entries');
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function saveRaw() {
        const editor = document.getElementById('hosts-raw-editor');
        if (!editor) return;

        const text = editor.value;

        try {
            const res = await API.put('/api/hosts/raw', { text });
            Toast.show(res.message || 'Файл сохранён', 'success');
            rawOriginal = text;
            rawHasChanges = false;
            onRawInput();

            // Обновляем данные для других вкладок
            const [statsRes, customRes] = await Promise.all([
                API.get('/api/hosts/stats'),
                API.get('/api/hosts/custom'),
            ]);
            stats = statsRes.stats || {};
            entries = customRes.entries || [];
            renderStats();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function refreshRaw() {
        if (rawHasChanges && !confirm('Есть несохранённые изменения. Перезагрузить?')) return;
        renderRawTab();
    }

    // ══════════════════ Preset Modal ══════════════════

    function openPresetModal(presetId) {
        const preset = presets.find(p => p.id === presetId);
        if (!preset) return;

        const modal = document.getElementById('hosts-preset-modal');
        const title = document.getElementById('hosts-preset-modal-title');
        const body = document.getElementById('hosts-preset-modal-body');
        if (!modal || !body) return;

        title.textContent = preset.name;

        let entriesHtml = '';
        preset.entries.forEach((e, i) => {
            entriesHtml += `
                <div style="display:flex; gap:8px; margin-bottom:6px; align-items:center;">
                    <input type="text" class="form-input" value="${escapeAttr(e.ip)}"
                           id="preset-entry-ip-${i}"
                           style="flex:1; font-family:var(--font-mono); font-size:12px;">
                    <span style="color:var(--text-muted); font-size:13px;">→</span>
                    <input type="text" class="form-input" value="${escapeAttr(e.domain)}"
                           id="preset-entry-domain-${i}" readonly
                           style="flex:2; font-family:var(--font-mono); font-size:12px; opacity:0.8;">
                </div>
            `;
        });

        body.innerHTML = `
            <div style="font-size:12px; color:var(--text-secondary); margin-bottom:12px;">
                ${escapeHtml(preset.description)}<br>
                <span style="color:var(--text-muted);">Вы можете изменить IP-адреса перед применением.</span>
            </div>
            <div style="max-height:350px; overflow-y:auto; padding-right:8px;" id="preset-entries-list">
                ${entriesHtml}
            </div>
            <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                <button class="btn btn-ghost" onclick="HostsPage.closePresetModal()">Отмена</button>
                <button class="btn btn-primary" onclick="HostsPage.applyPresetFromModal('${escapeAttr(presetId)}', ${preset.entries.length})">
                    Применить
                </button>
            </div>
        `;

        modal.style.display = 'flex';
    }

    function closePresetModal() {
        const modal = document.getElementById('hosts-preset-modal');
        if (modal) modal.style.display = 'none';
    }

    async function applyPresetFromModal(presetId, count) {
        // Собираем отредактированные записи
        const customEntries = [];
        for (let i = 0; i < count; i++) {
            const ipEl = document.getElementById(`preset-entry-ip-${i}`);
            const domainEl = document.getElementById(`preset-entry-domain-${i}`);
            if (ipEl && domainEl) {
                customEntries.push({
                    ip: ipEl.value.trim(),
                    domain: domainEl.value.trim(),
                });
            }
        }

        try {
            const res = await API.post('/api/hosts/preset', {
                name: presetId,
                entries: customEntries,
            });
            Toast.show(res.message || 'Пресет применён', 'success');
            closePresetModal();
            await refreshData();
            switchTab('entries');
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    // ══════════════════ Backup / Restore ══════════════════

    async function doBackup() {
        try {
            const res = await API.post('/api/hosts/backup');
            Toast.show(res.message || 'Бэкап создан', 'success');
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    async function showRestoreModal() {
        const modal = document.getElementById('hosts-restore-modal');
        const body = document.getElementById('hosts-restore-body');
        if (!modal || !body) return;

        modal.style.display = 'flex';
        body.innerHTML = '<div style="text-align:center; padding:24px; color:var(--text-muted);">Загрузка списка бэкапов...</div>';

        try {
            const res = await API.get('/api/hosts/backups');
            const backups = res.backups || [];

            if (backups.length === 0) {
                body.innerHTML = `
                    <div style="text-align:center; padding:24px; color:var(--text-muted);">
                        Бэкапы не найдены. Создайте бэкап перед внесением изменений.
                    </div>
                    <div style="display:flex; justify-content:flex-end; margin-top:12px;">
                        <button class="btn btn-ghost" onclick="HostsPage.closeRestoreModal()">Закрыть</button>
                    </div>
                `;
                return;
            }

            let html = '<div style="max-height:300px; overflow-y:auto;">';
            backups.forEach(b => {
                const date = b.timestamp ? new Date(b.timestamp * 1000).toLocaleString('ru-RU') : 'Неизвестно';
                const size = b.size ? formatSize(b.size) : '—';

                html += `
                    <div style="
                        display:flex; justify-content:space-between; align-items:center;
                        padding:10px 12px;
                        border-bottom:1px solid var(--border);
                    ">
                        <div>
                            <div style="font-size:13px; font-family:var(--font-mono); color:var(--text-primary);">
                                ${escapeHtml(b.filename)}
                            </div>
                            <div style="font-size:11px; color:var(--text-muted);">
                                ${date} · ${size}
                            </div>
                        </div>
                        <button class="btn btn-ghost btn-sm" onclick="HostsPage.doRestore('${escapeAttr(b.path)}')">
                            Восстановить
                        </button>
                    </div>
                `;
            });
            html += '</div>';

            html += `
                <div style="display:flex; justify-content:flex-end; margin-top:12px;">
                    <button class="btn btn-ghost" onclick="HostsPage.closeRestoreModal()">Закрыть</button>
                </div>
            `;

            body.innerHTML = html;
        } catch (err) {
            body.innerHTML = `
                <div style="text-align:center; padding:24px; color:var(--error);">
                    Ошибка загрузки: ${err.message}
                </div>
                <div style="display:flex; justify-content:flex-end; margin-top:12px;">
                    <button class="btn btn-ghost" onclick="HostsPage.closeRestoreModal()">Закрыть</button>
                </div>
            `;
        }
    }

    function closeRestoreModal() {
        const modal = document.getElementById('hosts-restore-modal');
        if (modal) modal.style.display = 'none';
    }

    async function doRestore(path) {
        if (!confirm('Восстановить /etc/hosts из этого бэкапа?\nТекущий файл будет заменён.')) return;

        try {
            const res = await API.post('/api/hosts/restore', { path });
            Toast.show(res.message || 'Восстановлено из бэкапа', 'success');
            closeRestoreModal();
            await loadData();
        } catch (err) {
            Toast.show(err.message, 'error');
        }
    }

    // ══════════════════ Утилиты ══════════════════

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escapeAttr(str) {
        if (!str) return '';
        return str.replace(/'/g, "\\'").replace(/"/g, '&quot;').replace(/\\/g, '\\\\');
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        switchTab,
        addEntry,
        removeEntry,
        quickBlock,
        clearAll,
        applyPreset,
        openPresetModal,
        closePresetModal,
        applyPresetFromModal,
        doBackup,
        showRestoreModal,
        closeRestoreModal,
        doRestore,
        saveRaw,
        refreshRaw,
        refreshData,
    };
})();
