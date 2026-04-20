/**
 * ipsets.js — Страница управления IP-списками.
 *
 * Табы: встроенные (ipset-base.txt, my-ipset.txt) + любые пользовательские
 *       IP-списки (файлы ipset-*.txt / my-ipset-*.txt в директории списков).
 * Функции: просмотр, редактирование, добавление IP/CIDR,
 *          загрузка по ASN через RIPE API, сброс к дефолтам,
 *          создание/переименование/удаление пользовательских IP-списков.
 */

const IPSetsPage = (() => {

    // Табы заполняются динамически из /api/ipsets
    let tabs = [];          // [{name, label, desc, is_builtin}]
    let activeTab = 'ipset-base';
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
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                        </svg>
                        IP-списки
                    </h1>
                    <p class="page-description">Управление ipset-файлами для nfqws2</p>
                </div>
                <button class="btn btn-primary" onclick="IPSetsPage.showCreateModal()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                    </svg>
                    Создать список
                </button>
            </div>

            <!-- Статистика -->
            <div class="status-grid" id="ip-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <!-- Табы -->
            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="ip-tabs"></div>

                <div class="lists-content" id="ip-content">
                    <div class="lists-toolbar">
                        <div class="lists-toolbar-left">
                            <span class="lists-tab-desc" id="ip-tab-desc"></span>
                            <span class="lists-unsaved" id="ip-unsaved" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
                                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                                </svg>
                                Несохранённые изменения
                            </span>
                        </div>
                        <div class="lists-toolbar-right">
                            <button class="btn btn-ghost btn-sm" onclick="IPSetsPage.resetList()" title="Сбросить к дефолтам">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="1 4 1 10 7 10"/>
                                    <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                                </svg>
                                Сбросить
                            </button>
                            <button class="btn btn-ghost btn-sm" id="ip-rename-btn" onclick="IPSetsPage.showRenameModal()" title="Переименовать список" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                                Переименовать
                            </button>
                            <button class="btn btn-ghost btn-sm" id="ip-delete-btn" onclick="IPSetsPage.deleteList()" title="Удалить список" style="display:none; color:var(--error);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                                Удалить
                            </button>
                            <button class="btn btn-primary btn-sm" id="ip-save-btn" onclick="IPSetsPage.saveList()" disabled>
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1-2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить
                            </button>
                        </div>
                    </div>

                    <!-- Основной textarea -->
                    <textarea class="lists-editor" id="ip-editor"
                              placeholder="Один IP или подсеть на строку...&#10;1.2.3.4&#10;10.0.0.0/8&#10;2001:db8::/32"
                              spellcheck="false"></textarea>

                    <!-- Добавление записей -->
                    <div class="lists-add-section">
                        <div class="lists-add-header">
                            <span class="form-label" style="margin:0;">Быстрое добавление</span>
                        </div>
                        <div class="lists-add-row">
                            <input type="text" class="form-input" id="ip-add-input"
                                   placeholder="IP-адрес или CIDR (1.2.3.4, 10.0.0.0/8)"
                                   onkeydown="if(event.key==='Enter') IPSetsPage.quickAdd()">
                            <button class="btn btn-ghost btn-sm" onclick="IPSetsPage.quickAdd()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                                </svg>
                                Добавить
                            </button>
                        </div>
                    </div>

                    <!-- Загрузка по ASN -->
                    <div class="lists-add-section" style="margin-top: 12px;">
                        <div class="lists-add-header">
                            <span class="form-label" style="margin:0;">Загрузка по ASN</span>
                            <span class="form-hint" style="margin:0;">RIPE API — загружает все анонсированные префиксы</span>
                        </div>
                        <div class="lists-add-row">
                            <input type="text" class="form-input" id="ip-asn-input"
                                   placeholder="Номер ASN (напр. 13335 для Cloudflare)"
                                   onkeydown="if(event.key==='Enter') IPSetsPage.loadASN()">
                            <select class="form-input" id="ip-asn-target" style="max-width:200px;">
                                <!-- опции подставляются динамически -->
                            </select>
                            <button class="btn btn-primary btn-sm" id="ip-asn-btn" onclick="IPSetsPage.loadASN()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                    <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                                </svg>
                                Загрузить
                            </button>
                        </div>
                        <div class="asn-presets">
                            <span class="form-hint">Популярные:</span>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('13335')">Cloudflare (13335)</button>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('15169')">Google (15169)</button>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('32934')">Facebook (32934)</button>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('14618')">Amazon (14618)</button>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('8075')">Microsoft (8075)</button>
                            <button class="btn-chip" onclick="IPSetsPage.setASN('36492')">Google (36492)</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Модальное окно создания списка -->
            <div class="modal-backdrop" id="ip-create-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Создать новый IP-список</h3>
                        <button class="modal-close" onclick="IPSetsPage.closeCreateModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Имя списка</label>
                            <input type="text" class="form-input" id="ip-create-name"
                                   placeholder="ipset-myvpn" autocomplete="off"
                                   onkeydown="if(event.key==='Enter') IPSetsPage.createList()">
                            <div class="form-hint">
                                Имя должно начинаться с <code>ipset-</code>, <code>ipset_</code>,
                                <code>my-ipset-</code> или <code>my-ipset_</code>.
                                Будет создан файл <code>&lt;имя&gt;.txt</code>.
                            </div>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="IPSetsPage.closeCreateModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="IPSetsPage.createList()">Создать</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Модальное окно переименования списка -->
            <div class="modal-backdrop" id="ip-rename-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Переименовать IP-список</h3>
                        <button class="modal-close" onclick="IPSetsPage.closeRenameModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Текущее имя</label>
                            <input type="text" class="form-input" id="ip-rename-old" readonly style="opacity:0.6;">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Новое имя</label>
                            <input type="text" class="form-input" id="ip-rename-new"
                                   placeholder="ipset-new-name" autocomplete="off"
                                   onkeydown="if(event.key==='Enter') IPSetsPage.renameList()">
                            <div class="form-hint">
                                Имя должно начинаться с <code>ipset-</code>, <code>ipset_</code>,
                                <code>my-ipset-</code> или <code>my-ipset_</code>.
                            </div>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="IPSetsPage.closeRenameModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="IPSetsPage.renameList()">Переименовать</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Загружаем данные
        loadStats();

        // Слушаем изменения
        const editor = document.getElementById('ip-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
        }
    }

    // ══════════════════ Tabs ══════════════════

    function renderTabs() {
        const tabsEl = document.getElementById('ip-tabs');
        if (!tabsEl) return;

        if (!tabs.find(t => t.name === activeTab) && tabs.length > 0) {
            activeTab = tabs[0].name;
        }

        tabsEl.innerHTML = tabs.map(t => `
            <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                    data-tab="${escapeAttr(t.name)}"
                    onclick="IPSetsPage.switchTab('${escapeAttr(t.name)}')"
                    title="${escapeAttr(t.desc)}">
                <span class="lists-tab-name">${escapeHtml(t.label)}</span>
                <span class="lists-tab-count" id="ip-tab-count-${escapeAttr(t.name)}">—</span>
            </button>
        `).join('');
    }

    function renderAsnTargetOptions() {
        const select = document.getElementById('ip-asn-target');
        if (!select) return;
        const prev = select.value;
        select.innerHTML = tabs.map(t =>
            `<option value="${escapeAttr(t.name)}">${escapeHtml(t.label)}</option>`
        ).join('');
        // Восстановить выбор: предыдущий → active → my-ipset → первый
        const candidates = [prev, activeTab, 'my-ipset'];
        for (const c of candidates) {
            if (c && tabs.find(t => t.name === c)) {
                select.value = c;
                return;
            }
        }
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
            const result = await API.get('/api/ipsets');
            if (!result.ok) return;

            tabs = tabsFromFiles(result.files || []);
            renderTabs();
            renderAsnTargetOptions();

            const grid = document.getElementById('ip-stats-grid');
            if (grid) {
                grid.innerHTML = (result.files || []).map(f => `
                    <div class="status-card" style="cursor:pointer;" onclick="IPSetsPage.switchTab('${escapeAttr(f.name)}')">
                        <div class="status-card-header">
                            <svg class="status-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <line x1="2" y1="12" x2="22" y2="12"/>
                                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
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

            // Обновляем счётчики
            (result.files || []).forEach(f => {
                const cnt = document.getElementById('ip-tab-count-' + f.name);
                if (cnt) cnt.textContent = f.count;
            });

            loadTab(activeTab);
        } catch (err) {
            console.error('loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('ip-editor');
        const desc = document.getElementById('ip-tab-desc');
        const deleteBtn = document.getElementById('ip-delete-btn');
        const renameBtn = document.getElementById('ip-rename-btn');

        if (editor) editor.value = 'Загрузка...';
        if (editor) editor.disabled = true;

        const tab = tabs.find(t => t.name === name);
        if (desc && tab) desc.textContent = tab.desc;

        if (deleteBtn) deleteBtn.style.display = (tab && !tab.is_builtin) ? '' : 'none';
        if (renameBtn) renameBtn.style.display = (tab && !tab.is_builtin) ? '' : 'none';

        try {
            const result = await API.get('/api/ipsets/' + encodeURIComponent(name));
            if (!result.ok) {
                if (editor) editor.value = 'Ошибка: ' + (result.error || '?');
                return;
            }

            const text = (result.entries || []).join('\n');
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

        document.querySelectorAll('#ip-tabs .lists-tab').forEach(el => {
            el.classList.toggle('active', el.dataset.tab === name);
        });

        loadTab(name);
    }

    // ══════════════════ Editor ══════════════════

    function onEditorInput() {
        if (loading) return;
        const editor = document.getElementById('ip-editor');
        if (!editor) return;
        setUnsaved(editor.value !== originalContent);
    }

    function setUnsaved(val) {
        hasUnsaved = val;
        const indicator = document.getElementById('ip-unsaved');
        const saveBtn = document.getElementById('ip-save-btn');
        if (indicator) indicator.style.display = val ? 'inline-flex' : 'none';
        if (saveBtn) saveBtn.disabled = !val;
    }

    // ══════════════════ Actions ══════════════════

    async function saveList() {
        const editor = document.getElementById('ip-editor');
        if (!editor) return;

        const text = editor.value.trim();
        const entries = text ? text.split('\n').map(e => e.trim()).filter(Boolean) : [];

        try {
            const result = await API.put('/api/ipsets/' + encodeURIComponent(activeTab), { entries });
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
            const result = await API.post('/api/ipsets/' + encodeURIComponent(activeTab) + '/reset');
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
        if (!confirm('Удалить IP-список ' + tab.label + '?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.delete('/api/ipsets/' + encodeURIComponent(activeTab));
            if (result.ok) {
                Toast.success(result.message || 'Список удалён');
                activeTab = 'ipset-base';
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
        const input = document.getElementById('ip-add-input');
        if (!input || !input.value.trim()) return;

        const editor = document.getElementById('ip-editor');
        if (!editor) return;

        const entry = input.value.trim();

        const current = editor.value.trim();
        if (current) {
            editor.value = current + '\n' + entry;
        } else {
            editor.value = entry;
        }

        input.value = '';
        setUnsaved(true);
        Toast.info('Добавлено в редактор. Нажмите "Сохранить" для применения.');
    }

    // ══════════════════ Create Modal ══════════════════

    const IPSET_NAME_RE = /^(?:ipset-base|my-ipset|ipset[-_][a-zA-Z0-9_-]+|my-ipset[-_][a-zA-Z0-9_-]+)$/;

    function showCreateModal() {
        const modal = document.getElementById('ip-create-modal');
        const input = document.getElementById('ip-create-name');
        if (modal) modal.style.display = 'flex';
        if (input) {
            input.value = 'ipset-';
            setTimeout(() => {
                input.focus();
                input.setSelectionRange(input.value.length, input.value.length);
            }, 50);
        }
    }

    function closeCreateModal() {
        const modal = document.getElementById('ip-create-modal');
        if (modal) modal.style.display = 'none';
    }

    async function createList() {
        const input = document.getElementById('ip-create-name');
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
        if (!IPSET_NAME_RE.test(name)) {
            Toast.error('Имя должно начинаться с "ipset-", "ipset_", "my-ipset-" или "my-ipset_"');
            return;
        }

        try {
            const result = await API.post('/api/ipsets/create', { name });
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

    // ══════════════════ Rename Modal ══════════════════

    function showRenameModal() {
        const tab = tabs.find(t => t.name === activeTab);
        if (!tab || tab.is_builtin) {
            Toast.warning('Нельзя переименовать встроенный список');
            return;
        }
        if (hasUnsaved) {
            if (!confirm('Есть несохранённые изменения. Переименовать список? Изменения будут потеряны.')) return;
        }

        const modal = document.getElementById('ip-rename-modal');
        const oldInput = document.getElementById('ip-rename-old');
        const newInput = document.getElementById('ip-rename-new');
        if (oldInput) oldInput.value = activeTab;
        if (newInput) {
            newInput.value = activeTab;
            setTimeout(() => {
                newInput.focus();
                newInput.select();
            }, 50);
        }
        if (modal) modal.style.display = 'flex';
    }

    function closeRenameModal() {
        const modal = document.getElementById('ip-rename-modal');
        if (modal) modal.style.display = 'none';
    }

    async function renameList() {
        const newInput = document.getElementById('ip-rename-new');
        if (!newInput) return;

        const newName = newInput.value.trim();
        if (!newName) {
            Toast.warning('Введите новое имя');
            return;
        }
        if (newName === activeTab) {
            closeRenameModal();
            return;
        }
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(newName)) {
            Toast.error('Недопустимое имя. Разрешены латиница, цифры, "_" и "-" (1..64 символов)');
            return;
        }
        if (!IPSET_NAME_RE.test(newName)) {
            Toast.error('Имя должно начинаться с "ipset-", "ipset_", "my-ipset-" или "my-ipset_"');
            return;
        }

        try {
            const result = await API.post('/api/ipsets/' + encodeURIComponent(activeTab) + '/rename', { new_name: newName });
            if (result.ok) {
                Toast.success(result.message || 'Список переименован');
                closeRenameModal();
                activeTab = newName;
                hasUnsaved = false;
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка переименования');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ ASN Loading ══════════════════

    function setASN(asn) {
        const input = document.getElementById('ip-asn-input');
        if (input) input.value = asn;
    }

    async function loadASN() {
        const input = document.getElementById('ip-asn-input');
        const targetSelect = document.getElementById('ip-asn-target');
        const btn = document.getElementById('ip-asn-btn');

        if (!input || !input.value.trim()) {
            Toast.warning('Введите номер ASN');
            return;
        }

        const asn = input.value.trim().replace(/^AS/i, '');
        const target = targetSelect ? targetSelect.value : 'my-ipset';

        if (btn) btn.disabled = true;

        try {
            Toast.info('Загрузка IP для ASN ' + asn + '...');

            const result = await API.post('/api/ipsets/load-asn', {
                asn: asn,
                target: target
            });

            if (result.ok) {
                Toast.success(result.message || 'Загружено');
                input.value = '';

                if (target === activeTab) {
                    loadTab(activeTab);
                }
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка загрузки ASN');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            if (btn) btn.disabled = false;
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
        setASN,
        loadASN,
        showCreateModal,
        closeCreateModal,
        createList,
        showRenameModal,
        closeRenameModal,
        renameList,
    };
})();
