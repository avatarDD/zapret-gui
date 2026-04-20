/**
 * hostlists.js — Страница управления списками доменов.
 *
 * Табы: встроенные списки (other.txt, other2.txt, netrogat.txt)
 *       + любые пользовательские списки, обнаруженные на сервере.
 * Функции: просмотр, редактирование, добавление, удаление,
 *          импорт из URL/текста, сброс к дефолтам,
 *          создание/удаление пользовательских списков.
 */

const HostlistsPage = (() => {

    const BUILTIN_DESC = {
        other: 'Базовый список доменов',
        other2: 'Пользовательские домены',
        netrogat: 'Исключения (не обрабатываются)',
    };

    // Динамический список табов, заполняется из /api/hostlists
    let tabs = [];          // [{name, label, desc, is_builtin}]
    let activeTab = 'other';
    let originalContent = '';
    let hasUnsaved = false;
    let loading = false;

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
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
                <button class="btn btn-primary" onclick="HostlistsPage.showCreateModal()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                    </svg>
                    Создать список
                </button>
            </div>

            <!-- Статистика -->
            <div class="status-grid" id="hl-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <!-- Табы -->
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
                            <button class="btn btn-ghost btn-sm" onclick="HostlistsPage.showImportModal()" title="Импорт">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                    <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                                </svg>
                                Импорт
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="HostlistsPage.resetList()" title="Сбросить к дефолтам">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="1 4 1 10 7 10"/>
                                    <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                                </svg>
                                Сбросить
                            </button>
                            <button class="btn btn-ghost btn-sm" id="hl-delete-btn" onclick="HostlistsPage.deleteList()" title="Удалить список" style="display:none; color:var(--error);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                                Удалить
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

                    <!-- Основной textarea -->
                    <textarea class="lists-editor" id="hl-editor"
                              placeholder="Один домен на строку...&#10;example.com&#10;sub.example.com"
                              spellcheck="false"></textarea>

                    <!-- Добавление доменов -->
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

            <!-- Модальное окно импорта -->
            <div class="modal-backdrop" id="hl-import-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Импорт доменов</h3>
                        <button class="modal-close" onclick="HostlistsPage.closeImportModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Импорт из URL</label>
                            <div class="lists-add-row">
                                <input type="text" class="form-input" id="hl-import-url"
                                       placeholder="https://example.com/domains.txt">
                                <button class="btn btn-primary btn-sm" onclick="HostlistsPage.importFromUrl()">
                                    Загрузить
                                </button>
                            </div>
                            <div class="form-hint">Текстовый файл — один домен на строку</div>
                        </div>
                        <div class="form-group" style="margin-top:16px;">
                            <label class="form-label">Или вставьте текст</label>
                            <textarea class="form-textarea" id="hl-import-text" rows="8"
                                      placeholder="youtube.com&#10;discord.com&#10;telegram.org"></textarea>
                            <button class="btn btn-primary btn-sm" style="margin-top:8px;"
                                    onclick="HostlistsPage.importFromText()">
                                Импортировать
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Модальное окно создания списка -->
            <div class="modal-backdrop" id="hl-create-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Создать новый список</h3>
                        <button class="modal-close" onclick="HostlistsPage.closeCreateModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Имя списка</label>
                            <input type="text" class="form-input" id="hl-create-name"
                                   placeholder="myvpn" autocomplete="off"
                                   onkeydown="if(event.key==='Enter') HostlistsPage.createList()">
                            <div class="form-hint">
                                Будет создан файл <code>&lt;имя&gt;.txt</code>.
                                Разрешены латиница, цифры, <code>_</code> и <code>-</code> (1..64 символов).
                            </div>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="HostlistsPage.closeCreateModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="HostlistsPage.createList()">Создать</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Загружаем данные
        loadStats();

        // Слушаем изменения в textarea
        const editor = document.getElementById('hl-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
        }
    }

    // ══════════════════ Tabs ══════════════════

    function renderTabs() {
        const tabsEl = document.getElementById('hl-tabs');
        if (!tabsEl) return;

        // Если активный таб больше не существует — переключаемся на первый доступный
        if (!tabs.find(t => t.name === activeTab) && tabs.length > 0) {
            activeTab = tabs[0].name;
        }

        tabsEl.innerHTML = tabs.map(t => `
            <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                    data-tab="${escapeAttr(t.name)}"
                    onclick="HostlistsPage.switchTab('${escapeAttr(t.name)}')"
                    title="${escapeAttr(t.desc)}">
                <span class="lists-tab-name">${escapeHtml(t.label)}</span>
                <span class="lists-tab-count" id="hl-tab-count-${escapeAttr(t.name)}">—</span>
            </button>
        `).join('');
    }

    function tabsFromFiles(files) {
        return files.map(f => ({
            name: f.name,
            label: f.filename || (f.name + '.txt'),
            desc: f.description || '',
            is_builtin: !!f.is_builtin,
        }));
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadStats() {
        try {
            const result = await API.get('/api/hostlists');
            if (!result.ok) return;

            tabs = tabsFromFiles(result.files || []);
            renderTabs();

            const grid = document.getElementById('hl-stats-grid');
            if (grid) {
                grid.innerHTML = (result.files || []).map(f => `
                    <div class="status-card" style="cursor:pointer;" onclick="HostlistsPage.switchTab('${escapeAttr(f.name)}')">
                        <div class="status-card-header">
                            <svg class="status-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                            </svg>
                            <span class="status-card-label">${escapeHtml(f.filename)}</span>
                            ${f.is_builtin ? '<span class="badge badge-muted" style="margin-left:auto;">builtin</span>'
                                           : '<span class="badge badge-accent" style="margin-left:auto;">user</span>'}
                        </div>
                        <div class="status-card-value">${f.count}</div>
                        <div class="status-card-detail">${escapeHtml(f.description || '')}</div>
                    </div>
                `).join('');
            }

            // Обновляем счётчики в табах
            (result.files || []).forEach(f => {
                const cnt = document.getElementById('hl-tab-count-' + f.name);
                if (cnt) cnt.textContent = f.count;
            });

            // Загружаем содержимое активной вкладки
            loadTab(activeTab);
        } catch (err) {
            console.error('loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('hl-editor');
        const desc = document.getElementById('hl-tab-desc');
        const deleteBtn = document.getElementById('hl-delete-btn');

        if (editor) editor.value = 'Загрузка...';
        if (editor) editor.disabled = true;

        const tab = tabs.find(t => t.name === name);
        if (desc && tab) desc.textContent = tab.desc;

        // Кнопка "Удалить" видна только для пользовательских списков
        if (deleteBtn) {
            deleteBtn.style.display = (tab && !tab.is_builtin) ? '' : 'none';
        }

        try {
            const result = await API.get('/api/hostlists/' + encodeURIComponent(name));
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

    // ══════════════════ Tab Switching ══════════════════

    function switchTab(name) {
        if (name === activeTab) return;

        if (hasUnsaved) {
            if (!confirm('Есть несохранённые изменения. Переключить таб?')) return;
        }

        activeTab = name;

        // Обновляем UI табов
        document.querySelectorAll('.lists-tab').forEach(el => {
            el.classList.toggle('active', el.dataset.tab === name);
        });

        loadTab(name);
    }

    // ══════════════════ Editor ══════════════════

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

    // ══════════════════ Actions ══════════════════

    async function saveList() {
        const editor = document.getElementById('hl-editor');
        if (!editor) return;

        const text = editor.value.trim();
        const domains = text ? text.split('\n').map(d => d.trim()).filter(Boolean) : [];

        try {
            const result = await API.put('/api/hostlists/' + encodeURIComponent(activeTab), { domains });
            if (result.ok) {
                Toast.success(result.message || 'Сохранено');
                originalContent = editor.value;
                setUnsaved(false);
                loadStats();

                if (result.invalid_count) {
                    Toast.warning('Пропущено невалидных: ' + result.invalid_count);
                }
            } else {
                Toast.error(result.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function resetList() {
        const tab = tabs.find(t => t.name === activeTab);
        const label = tab ? tab.label : activeTab;

        const msg = tab && tab.is_builtin
            ? 'Сбросить ' + label + ' к дефолтным значениям?'
            : 'Очистить ' + label + '? (у пользовательских списков нет дефолтов)';
        if (!confirm(msg)) return;

        try {
            const result = await API.post('/api/hostlists/' + encodeURIComponent(activeTab) + '/reset');
            if (result.ok) {
                Toast.success(result.message || 'Сброшено');
                loadTab(activeTab);
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка сброса');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function deleteList() {
        const tab = tabs.find(t => t.name === activeTab);
        if (!tab || tab.is_builtin) {
            Toast.warning('Нельзя удалить встроенный список');
            return;
        }
        if (!confirm('Удалить список ' + tab.label + '?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.delete('/api/hostlists/' + encodeURIComponent(activeTab));
            if (result.ok) {
                Toast.success(result.message || 'Список удалён');
                // Переключаемся на первую встроенную вкладку
                activeTab = 'other';
                hasUnsaved = false;
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка удаления');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function quickAdd() {
        const input = document.getElementById('hl-add-input');
        if (!input || !input.value.trim()) return;

        const editor = document.getElementById('hl-editor');
        if (!editor) return;

        const domain = input.value.trim();

        // Добавляем в textarea
        const current = editor.value.trim();
        if (current) {
            editor.value = current + '\n' + domain;
        } else {
            editor.value = domain;
        }

        input.value = '';
        setUnsaved(true);
        Toast.info('Добавлено в редактор. Нажмите "Сохранить" для применения.');
    }

    // ══════════════════ Create Modal ══════════════════

    function showCreateModal() {
        const modal = document.getElementById('hl-create-modal');
        const input = document.getElementById('hl-create-name');
        if (modal) modal.style.display = 'flex';
        if (input) {
            input.value = '';
            setTimeout(() => input.focus(), 50);
        }
    }

    function closeCreateModal() {
        const modal = document.getElementById('hl-create-modal');
        if (modal) modal.style.display = 'none';
    }

    async function createList() {
        const input = document.getElementById('hl-create-name');
        if (!input) return;

        const name = input.value.trim();
        if (!name) {
            Toast.warning('Введите имя списка');
            return;
        }

        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
            Toast.error('Недопустимое имя. Разрешены латиница, цифры, "_" и "-" (1..64 символов)');
            return;
        }

        try {
            const result = await API.post('/api/hostlists/create', { name });
            if (result.ok) {
                Toast.success(result.message || 'Список создан');
                closeCreateModal();
                activeTab = name;
                hasUnsaved = false;
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка создания');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ Import Modal ══════════════════

    function showImportModal() {
        const modal = document.getElementById('hl-import-modal');
        if (modal) modal.style.display = 'flex';
    }

    function closeImportModal() {
        const modal = document.getElementById('hl-import-modal');
        if (modal) modal.style.display = 'none';
        // Очищаем поля
        const urlInput = document.getElementById('hl-import-url');
        const textInput = document.getElementById('hl-import-text');
        if (urlInput) urlInput.value = '';
        if (textInput) textInput.value = '';
    }

    async function importFromUrl() {
        const urlInput = document.getElementById('hl-import-url');
        if (!urlInput || !urlInput.value.trim()) {
            Toast.warning('Введите URL');
            return;
        }

        try {
            Toast.info('Загрузка...');
            const result = await API.post('/api/hostlists/' + encodeURIComponent(activeTab) + '/import', {
                url: urlInput.value.trim()
            });
            if (result.ok) {
                Toast.success(result.message || 'Импортировано');
                closeImportModal();
                loadTab(activeTab);
                loadStats();
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
            const result = await API.post('/api/hostlists/' + encodeURIComponent(activeTab) + '/import', {
                text: textInput.value.trim()
            });
            if (result.ok) {
                Toast.success(result.message || 'Импортировано');
                closeImportModal();
                loadTab(activeTab);
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка импорта');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ Utils ══════════════════

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function escapeAttr(text) {
        return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ══════════════════ Lifecycle ══════════════════

    function destroy() {
        hasUnsaved = false;
        loading = false;
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        switchTab,
        saveList,
        resetList,
        deleteList,
        quickAdd,
        showCreateModal,
        closeCreateModal,
        createList,
        showImportModal,
        closeImportModal,
        importFromUrl,
        importFromText,
    };
})();
