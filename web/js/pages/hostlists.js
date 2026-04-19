/**
 * hostlists.js — Страница управления списками доменов.
 *
 * Поддерживает встроенные и пользовательские hostlist-файлы.
 */

const HostlistsPage = (() => {
    let tabs = [];
    let activeTab = 'other';
    let originalContent = '';
    let hasUnsaved = false;
    let loading = false;

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                        <line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/>
                        <line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/>
                        <line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>
                    </svg>
                    Списки доменов
                </h1>
                <p class="page-description">Управление hostlist-файлами для nfqws2</p>
            </div>

            <div class="status-grid" id="hl-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="hl-tabs"></div>

                <div class="lists-content" id="hl-content">
                    <div class="lists-toolbar">
                        <div class="lists-toolbar-left">
                            <span class="lists-tab-desc" id="hl-tab-desc"></span>
                            <span class="lists-unsaved" id="hl-unsaved" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
                                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                                </svg>
                                Несохранённые изменения
                            </span>
                        </div>
                        <div class="lists-toolbar-right">
                            <button class="btn btn-ghost btn-sm" onclick="HostlistsPage.showCreateModal()" title="Создать список">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                                </svg>
                                Создать список
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="HostlistsPage.showImportModal()" title="Импорт">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                    <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                                </svg>
                                Импорт
                            </button>
                            <button class="btn btn-ghost btn-sm" id="hl-delete-btn" onclick="HostlistsPage.deleteList()" title="Удалить список" style="display:none; color:var(--error);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                                Удалить
                            </button>
                            <button class="btn btn-ghost btn-sm" id="hl-reset-btn" onclick="HostlistsPage.resetList()" title="Сбросить к дефолтам">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                                </svg>
                                Сбросить
                            </button>
                            <button class="btn btn-primary btn-sm" id="hl-save-btn" onclick="HostlistsPage.saveList()" disabled>
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1-2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить
                            </button>
                        </div>
                    </div>

                    <textarea class="lists-editor" id="hl-editor"
                              placeholder="Один домен на строку...&#10;example.com&#10;sub.example.com"
                              spellcheck="false"></textarea>

                    <div class="lists-add-section">
                        <div class="lists-add-header">
                            <span class="form-label" style="margin:0;">Быстрое добавление</span>
                        </div>
                        <div class="lists-add-row">
                            <input type="text" class="form-input" id="hl-add-input"
                                   placeholder="Домен или URL (youtube.com, https://example.com/page)"
                                   onkeydown="if(event.key==='Enter') HostlistsPage.quickAdd()">
                            <button class="btn btn-ghost btn-sm" onclick="HostlistsPage.quickAdd()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                                </svg>
                                Добавить
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="modal-backdrop" id="hl-import-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Импорт доменов</h3>
                        <button class="modal-close" onclick="HostlistsPage.closeImportModal()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Импорт из URL</label>
                            <div class="lists-add-row">
                                <input type="text" class="form-input" id="hl-import-url" placeholder="https://example.com/domains.txt">
                                <button class="btn btn-primary btn-sm" onclick="HostlistsPage.importFromUrl()">Загрузить</button>
                            </div>
                            <div class="form-hint">Текстовый файл — один домен на строку</div>
                        </div>
                        <div class="form-group" style="margin-top:16px;">
                            <label class="form-label">Или вставьте текст</label>
                            <textarea class="form-textarea" id="hl-import-text" rows="8" placeholder="youtube.com&#10;discord.com&#10;telegram.org"></textarea>
                            <button class="btn btn-primary btn-sm" style="margin-top:8px;" onclick="HostlistsPage.importFromText()">Импортировать</button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="modal-backdrop" id="hl-create-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Создать список</h3>
                        <button class="modal-close" onclick="HostlistsPage.closeCreateModal()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Имя файла без .txt</label>
                            <input type="text" class="form-input" id="hl-create-name" placeholder="custom_udp_fake"
                                   onkeydown="if(event.key==='Enter') HostlistsPage.createList()">
                            <div class="form-hint">Разрешены латиница, цифры, _ и -</div>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="HostlistsPage.closeCreateModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="HostlistsPage.createList()">Создать</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        const editor = document.getElementById('hl-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
        }

        loadStats();
    }

    function getTabMeta(name) {
        return tabs.find(t => t.name === name) || null;
    }

    function renderTabs() {
        const tabsEl = document.getElementById('hl-tabs');
        if (!tabsEl) return;

        tabsEl.innerHTML = tabs.map(t => `
            <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                    data-tab="${t.name}"
                    onclick="HostlistsPage.switchTab('${t.name}')">
                <span class="lists-tab-name">${t.filename || (t.name + '.txt')}</span>
                <span class="lists-tab-count" id="hl-tab-count-${t.name}">${typeof t.count === 'number' ? t.count : '—'}</span>
            </button>
        `).join('');
    }

    function updateTabToolbar() {
        const tab = getTabMeta(activeTab);
        const desc = document.getElementById('hl-tab-desc');
        const resetBtn = document.getElementById('hl-reset-btn');
        const deleteBtn = document.getElementById('hl-delete-btn');

        if (desc) {
            desc.textContent = tab && tab.description ? tab.description : (tab && tab.is_default ? 'Встроенный список доменов' : 'Пользовательский список доменов');
        }
        if (resetBtn) {
            resetBtn.style.display = tab && tab.has_defaults ? 'inline-flex' : 'none';
        }
        if (deleteBtn) {
            deleteBtn.style.display = tab && !tab.is_default ? 'inline-flex' : 'none';
        }
    }

    async function loadStats(reloadActive = true) {
        try {
            const result = await API.get('/api/hostlists');
            if (!result.ok) return;

            tabs = result.files || [];
            if (!tabs.length) {
                tabs = [{ name: 'other', filename: 'other.txt', count: 0, is_default: true, has_defaults: true }];
            }

            if (!getTabMeta(activeTab)) {
                activeTab = tabs[0].name;
            }

            const grid = document.getElementById('hl-stats-grid');
            if (grid) {
                grid.innerHTML = tabs.map(f => `
                    <div class="status-card" style="cursor:pointer;" onclick="HostlistsPage.switchTab('${f.name}')">
                        <div class="status-card-header">
                            <svg class="status-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                            </svg>
                            <span class="status-card-label">${f.filename}</span>
                        </div>
                        <div class="status-card-value">${f.count}</div>
                        <div class="status-card-detail">${f.description || (f.is_default ? 'Встроенный список' : 'Пользовательский список')}</div>
                    </div>
                `).join('');
            }

            renderTabs();
            updateTabToolbar();

            if (reloadActive) {
                loadTab(activeTab);
            }
        } catch (err) {
            console.error('loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('hl-editor');

        if (editor) {
            editor.value = 'Загрузка...';
            editor.disabled = true;
        }

        updateTabToolbar();

        try {
            const result = await API.get('/api/hostlists/' + name);
            if (!result.ok) {
                if (editor) editor.value = 'Ошибка: ' + (result.error || '?');
                return;
            }

            const text = (result.domains || []).join('\n');
            if (editor) {
                editor.value = text;
                editor.disabled = false;
            }
            originalContent = text;
            setUnsaved(false);
        } catch (err) {
            if (editor) editor.value = 'Ошибка: ' + err.message;
        } finally {
            loading = false;
        }
    }

    function switchTab(name) {
        if (name === activeTab) return;
        if (hasUnsaved && !confirm('Есть несохранённые изменения. Переключить таб?')) return;

        activeTab = name;
        renderTabs();
        updateTabToolbar();
        loadTab(name);
    }

    function onEditorInput() {
        if (loading) return;
        const editor = document.getElementById('hl-editor');
        if (!editor) return;
        setUnsaved(editor.value !== originalContent);
    }

    function setUnsaved(val) {
        hasUnsaved = val;
        const indicator = document.getElementById('hl-unsaved');
        const saveBtn = document.getElementById('hl-save-btn');
        if (indicator) indicator.style.display = val ? 'inline-flex' : 'none';
        if (saveBtn) saveBtn.disabled = !val;
    }

    async function saveList() {
        const editor = document.getElementById('hl-editor');
        if (!editor) return;

        const text = editor.value.trim();
        const domains = text ? text.split('\n').map(d => d.trim()).filter(Boolean) : [];

        try {
            const result = await API.put('/api/hostlists/' + activeTab, { domains });
            if (!result.ok) {
                Toast.error(result.error || 'Ошибка сохранения');
                return;
            }

            Toast.success(result.message || 'Сохранено');
            originalContent = editor.value;
            setUnsaved(false);
            await loadStats(false);
            renderTabs();

            if (result.invalid_count) {
                Toast.warning('Пропущено невалидных: ' + result.invalid_count);
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function resetList() {
        const tab = getTabMeta(activeTab);
        const label = tab ? tab.filename : (activeTab + '.txt');

        if (!confirm('Сбросить ' + label + ' к дефолтным значениям?')) return;

        try {
            const result = await API.post('/api/hostlists/' + activeTab + '/reset');
            if (result.ok) {
                Toast.success(result.message || 'Сброшено');
                await loadStats(false);
                loadTab(activeTab);
            } else {
                Toast.error(result.error || 'Ошибка сброса');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function deleteList() {
        const tab = getTabMeta(activeTab);
        if (!tab || tab.is_default) return;

        if (!confirm('Удалить список ' + tab.filename + '?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.delete('/api/hostlists/' + activeTab);
            if (!result.ok) {
                Toast.error(result.error || 'Ошибка удаления');
                return;
            }

            Toast.success(result.message || 'Список удалён');
            activeTab = 'other';
            setUnsaved(false);
            await loadStats(true);
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function quickAdd() {
        const input = document.getElementById('hl-add-input');
        const editor = document.getElementById('hl-editor');
        if (!input || !editor || !input.value.trim()) return;

        const domain = input.value.trim();
        const current = editor.value.trim();
        editor.value = current ? current + '\n' + domain : domain;

        input.value = '';
        setUnsaved(true);
        Toast.info('Добавлено в редактор. Нажмите "Сохранить" для применения.');
    }

    function showImportModal() {
        const modal = document.getElementById('hl-import-modal');
        if (modal) modal.style.display = 'flex';
    }

    function closeImportModal() {
        const modal = document.getElementById('hl-import-modal');
        if (modal) modal.style.display = 'none';

        const urlInput = document.getElementById('hl-import-url');
        const textInput = document.getElementById('hl-import-text');
        if (urlInput) urlInput.value = '';
        if (textInput) textInput.value = '';
    }

    function showCreateModal() {
        const modal = document.getElementById('hl-create-modal');
        const input = document.getElementById('hl-create-name');
        if (modal) modal.style.display = 'flex';
        if (input) {
            input.value = '';
            setTimeout(() => input.focus(), 0);
        }
    }

    function closeCreateModal() {
        const modal = document.getElementById('hl-create-modal');
        const input = document.getElementById('hl-create-name');
        if (modal) modal.style.display = 'none';
        if (input) input.value = '';
    }

    async function createList() {
        const input = document.getElementById('hl-create-name');
        if (!input || !input.value.trim()) {
            Toast.warning('Введите имя списка');
            return;
        }

        try {
            const result = await API.post('/api/hostlists/create', {
                name: input.value.trim()
            });
            if (!result.ok) {
                Toast.error(result.error || 'Ошибка создания');
                return;
            }

            closeCreateModal();
            Toast.success(result.message || 'Список создан');
            activeTab = result.name;
            await loadStats(true);
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function importFromUrl() {
        const urlInput = document.getElementById('hl-import-url');
        if (!urlInput || !urlInput.value.trim()) {
            Toast.warning('Введите URL');
            return;
        }

        try {
            Toast.info('Загрузка...');
            const result = await API.post('/api/hostlists/' + activeTab + '/import', {
                url: urlInput.value.trim()
            });
            if (result.ok) {
                Toast.success(result.message || 'Импортировано');
                closeImportModal();
                await loadStats(false);
                loadTab(activeTab);
            } else {
                Toast.error(result.error || 'Ошибка импорта');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function importFromText() {
        const textInput = document.getElementById('hl-import-text');
        if (!textInput || !textInput.value.trim()) {
            Toast.warning('Вставьте текст с доменами');
            return;
        }

        try {
            const result = await API.post('/api/hostlists/' + activeTab + '/import', {
                text: textInput.value.trim()
            });
            if (result.ok) {
                Toast.success(result.message || 'Импортировано');
                closeImportModal();
                await loadStats(false);
                loadTab(activeTab);
            } else {
                Toast.error(result.error || 'Ошибка импорта');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function destroy() {
        hasUnsaved = false;
        loading = false;
        tabs = [];
    }

    return {
        render,
        destroy,
        switchTab,
        saveList,
        resetList,
        deleteList,
        quickAdd,
        showImportModal,
        closeImportModal,
        showCreateModal,
        closeCreateModal,
        createList,
        importFromUrl,
        importFromText,
    };
})();
