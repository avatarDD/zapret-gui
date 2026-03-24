/**
 * hostlists.js — Страница управления списками доменов.
 *
 * Табы: other.txt | other2.txt | netrogat.txt
 * Функции: просмотр, редактирование, добавление, удаление,
 *          импорт из URL/текста, сброс к дефолтам.
 */

const HostlistsPage = (() => {

    const TABS = [
        { name: 'other',    label: 'other.txt',    desc: 'Базовый список доменов' },
        { name: 'other2',   label: 'other2.txt',   desc: 'Пользовательские домены' },
        { name: 'netrogat', label: 'netrogat.txt',  desc: 'Исключения (не обрабатываются)' },
    ];

    let activeTab = 'other';
    let originalContent = '';
    let hasUnsaved = false;
    let loading = false;

    // ══════════════════ Render ══════════════════

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

            <!-- Статистика -->
            <div class="status-grid" id="hl-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <!-- Табы -->
            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="hl-tabs">
                    ${TABS.map(t => `
                        <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                                data-tab="${t.name}"
                                onclick="HostlistsPage.switchTab('${t.name}')">
                            <span class="lists-tab-name">${t.label}</span>
                            <span class="lists-tab-count" id="hl-tab-count-${t.name}">—</span>
                        </button>
                    `).join('')}
                </div>

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
        `;

        // Загружаем данные
        loadStats();
        loadTab(activeTab);

        // Слушаем изменения в textarea
        const editor = document.getElementById('hl-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
        }
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadStats() {
        try {
            const result = await API.get('/api/hostlists');
            if (!result.ok) return;

            const grid = document.getElementById('hl-stats-grid');
            if (!grid) return;

            grid.innerHTML = result.files.map(f => `
                <div class="status-card" style="cursor:pointer;" onclick="HostlistsPage.switchTab('${f.name}')">
                    <div class="status-card-header">
                        <svg class="status-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                        <span class="status-card-label">${f.filename}</span>
                    </div>
                    <div class="status-card-value">${f.count}</div>
                    <div class="status-card-detail">${f.description}</div>
                </div>
            `).join('');

            // Обновляем счётчики в табах
            result.files.forEach(f => {
                const cnt = document.getElementById('hl-tab-count-' + f.name);
                if (cnt) cnt.textContent = f.count;
            });
        } catch (err) {
            console.error('loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('hl-editor');
        const desc = document.getElementById('hl-tab-desc');

        if (editor) editor.value = 'Загрузка...';
        if (editor) editor.disabled = true;

        const tab = TABS.find(t => t.name === name);
        if (desc && tab) desc.textContent = tab.desc;

        try {
            const result = await API.get('/api/hostlists/' + name);
            if (!result.ok) {
                if (editor) editor.value = 'Ошибка: ' + (result.error || '?');
                return;
            }

            const text = result.domains.join('\n');
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
            const result = await API.put('/api/hostlists/' + activeTab, { domains });
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
        const tab = TABS.find(t => t.name === activeTab);
        const label = tab ? tab.label : activeTab;

        if (!confirm('Сбросить ' + label + ' к дефолтным значениям?')) return;

        try {
            const result = await API.post('/api/hostlists/' + activeTab + '/reset');
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
            const result = await API.post('/api/hostlists/' + activeTab + '/import', {
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
            const result = await API.post('/api/hostlists/' + activeTab + '/import', {
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
        quickAdd,
        showImportModal,
        closeImportModal,
        importFromUrl,
        importFromText,
    };
})();
