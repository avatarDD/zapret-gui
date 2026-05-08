/**
 * lua_scripts.js — Страница управления Lua-скриптами nfqws2.
 *
 * Возможности:
 *   - просмотр всех *.lua скриптов в lua_path (bundled + user);
 *   - редактирование с подсветкой синтаксиса (overlay над textarea);
 *   - проверка синтаксиса (luac/lua/builtin) с подсказкой ошибок;
 *   - создание / переименование / удаление пользовательских скриптов;
 *   - сброс bundled-скрипта к оригинальной версии.
 */

const LuaScriptsPage = (() => {

    let tabs = [];          // [{name, label, desc, is_builtin, modified}]
    let activeTab = null;
    let originalContent = '';
    let hasUnsaved = false;
    let loading = false;
    let lastCheck = null;   // {valid, errors, warnings, checker}
    let currentErrorLines = new Set();

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                            <polyline points="16 13 18 15 16 17"/>
                            <polyline points="8 17 6 15 8 13"/>
                        </svg>
                        Lua-скрипты
                    </h1>
                    <p class="page-description">
                        Скрипты в <code>lua_path</code> для <code>--lua-init=@lua/&lt;имя&gt;.lua</code>
                    </p>
                </div>
                <button class="btn btn-primary" onclick="LuaScriptsPage.showCreateModal()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                    </svg>
                    Создать скрипт
                </button>
            </div>

            <div class="status-grid" id="lua-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="lua-tabs"></div>

                <div class="lists-content" id="lua-content">
                    <div class="lists-toolbar">
                        <div class="lists-toolbar-left">
                            <span class="lists-tab-desc" id="lua-tab-desc"></span>
                            <span class="lists-unsaved" id="lua-unsaved" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
                                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                                </svg>
                                Несохранённые изменения
                            </span>
                        </div>
                        <div class="lists-toolbar-right">
                            <button class="btn btn-ghost btn-sm" onclick="LuaScriptsPage.checkSyntax()" title="Проверить синтаксис">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="9 11 12 14 22 4"/>
                                    <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                                </svg>
                                Проверить
                            </button>
                            <button class="btn btn-ghost btn-sm" id="lua-reset-btn" onclick="LuaScriptsPage.resetScript()" title="Восстановить bundled-версию" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="1 4 1 10 7 10"/>
                                    <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                                </svg>
                                Сбросить
                            </button>
                            <button class="btn btn-ghost btn-sm" id="lua-rename-btn" onclick="LuaScriptsPage.showRenameModal()" title="Переименовать" style="display:none;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                                Переименовать
                            </button>
                            <button class="btn btn-ghost btn-sm" id="lua-delete-btn" onclick="LuaScriptsPage.deleteScript()" title="Удалить скрипт" style="display:none; color:var(--error);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                                Удалить
                            </button>
                            <button class="btn btn-primary btn-sm" id="lua-save-btn" onclick="LuaScriptsPage.saveScript()" disabled>
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1-2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить
                            </button>
                        </div>
                    </div>

                    <!-- Code editor: textarea + overlay highlight -->
                    <div class="lua-editor-wrap" id="lua-editor-wrap">
                        <div class="lua-gutter" id="lua-gutter"></div>
                        <pre class="lua-highlight" aria-hidden="true"><code id="lua-highlight"></code></pre>
                        <textarea class="lua-editor" id="lua-editor"
                                  spellcheck="false" autocomplete="off"
                                  autocapitalize="off" autocorrect="off"
                                  placeholder="-- Напишите Lua-код здесь&#10;function my_desync(ctx, desync)&#10;    -- ...&#10;end"></textarea>
                    </div>

                    <!-- Errors panel -->
                    <div class="lua-errors" id="lua-errors" style="display:none;"></div>
                </div>
            </div>

            <!-- Create modal -->
            <div class="modal-backdrop" id="lua-create-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Создать новый Lua-скрипт</h3>
                        <button class="modal-close" onclick="LuaScriptsPage.closeCreateModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Имя скрипта</label>
                            <input type="text" class="form-input" id="lua-create-name"
                                   placeholder="my_script" autocomplete="off"
                                   onkeydown="if(event.key==='Enter') LuaScriptsPage.createScript()">
                            <div class="form-hint">
                                Будет создан файл <code>&lt;имя&gt;.lua</code>.
                                Разрешены латиница, цифры, <code>_</code>, <code>-</code>, <code>.</code>
                                (1..128 символов).
                            </div>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="LuaScriptsPage.closeCreateModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="LuaScriptsPage.createScript()">Создать</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Rename modal -->
            <div class="modal-backdrop" id="lua-rename-modal" style="display:none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Переименовать скрипт</h3>
                        <button class="modal-close" onclick="LuaScriptsPage.closeRenameModal()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Текущее имя</label>
                            <input type="text" class="form-input" id="lua-rename-old" readonly style="opacity:0.6;">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Новое имя</label>
                            <input type="text" class="form-input" id="lua-rename-new"
                                   placeholder="new_name" autocomplete="off"
                                   onkeydown="if(event.key==='Enter') LuaScriptsPage.renameScript()">
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="LuaScriptsPage.closeRenameModal()">Отмена</button>
                            <button class="btn btn-primary" onclick="LuaScriptsPage.renameScript()">Переименовать</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        loadStats();

        const editor = document.getElementById('lua-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
            editor.addEventListener('scroll', syncScroll);
            editor.addEventListener('keydown', onEditorKey);
        }
    }

    // ══════════════════ Tabs ══════════════════

    function tabsFromFiles(files) {
        return files.map(f => ({
            name: f.name,
            label: f.filename || (f.name + '.lua'),
            is_builtin: !!f.is_builtin,
            modified_from_bundled: !!f.modified_from_bundled,
            size: f.size || 0,
            lines: f.lines || 0,
        }));
    }

    function renderTabs() {
        const tabsEl = document.getElementById('lua-tabs');
        if (!tabsEl) return;

        if (!tabs.find(t => t.name === activeTab) && tabs.length > 0) {
            activeTab = tabs[0].name;
        }

        tabsEl.innerHTML = tabs.map(t => `
            <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                    data-tab="${escapeAttr(t.name)}"
                    onclick="LuaScriptsPage.switchTab('${escapeAttr(t.name)}')"
                    title="${escapeAttr(t.label)}${t.modified_from_bundled ? ' (изменён)' : ''}">
                <span class="lists-tab-name">${escapeHtml(t.label)}</span>
                <span class="lists-tab-count">${t.lines}</span>
                ${t.is_builtin ? '' : '<span class="badge badge-accent" style="font-size:9px;">user</span>'}
                ${t.modified_from_bundled ? '<span class="badge badge-muted" style="font-size:9px;">mod</span>' : ''}
            </button>
        `).join('');
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadStats() {
        try {
            const result = await API.get('/api/lua');
            if (!result.ok) return;

            tabs = tabsFromFiles(result.files || []);

            if (!activeTab && tabs.length > 0) {
                activeTab = tabs[0].name;
            }

            renderTabs();

            const grid = document.getElementById('lua-stats-grid');
            if (grid) {
                const total = tabs.length;
                const builtin = tabs.filter(t => t.is_builtin).length;
                const user = total - builtin;
                const modified = tabs.filter(t => t.modified_from_bundled).length;
                const totalSize = (result.files || []).reduce((s, f) => s + (f.size || 0), 0);

                grid.innerHTML = `
                    <div class="status-card">
                        <div class="status-card-label">Всего скриптов</div>
                        <div class="status-card-value">${total}</div>
                        <div class="status-card-detail">${formatBytes(totalSize)}</div>
                    </div>
                    <div class="status-card">
                        <div class="status-card-label">Bundled</div>
                        <div class="status-card-value">${builtin}</div>
                        <div class="status-card-detail">из комплекта GUI</div>
                    </div>
                    <div class="status-card">
                        <div class="status-card-label">Пользовательские</div>
                        <div class="status-card-value">${user}</div>
                        <div class="status-card-detail">созданы вручную</div>
                    </div>
                    <div class="status-card">
                        <div class="status-card-label">Изменены</div>
                        <div class="status-card-value">${modified}</div>
                        <div class="status-card-detail">отличаются от bundled</div>
                    </div>
                `;
            }

            if (activeTab) loadTab(activeTab);
        } catch (err) {
            console.error('lua loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('lua-editor');
        const desc = document.getElementById('lua-tab-desc');

        if (editor) {
            editor.value = '-- Загрузка...';
            editor.disabled = true;
        }
        clearErrors();

        const tab = tabs.find(t => t.name === name);
        const renameBtn = document.getElementById('lua-rename-btn');
        const deleteBtn = document.getElementById('lua-delete-btn');
        const resetBtn = document.getElementById('lua-reset-btn');

        if (tab) {
            if (desc) {
                const tags = [];
                if (tab.is_builtin) tags.push('bundled');
                if (tab.modified_from_bundled) tags.push('изменён');
                tags.push(`${tab.lines} стр.`, formatBytes(tab.size));
                desc.textContent = tab.label + ' — ' + tags.join(' · ');
            }
            if (deleteBtn) deleteBtn.style.display = tab.is_builtin ? 'none' : '';
            if (renameBtn) renameBtn.style.display = tab.is_builtin ? 'none' : '';
            if (resetBtn) resetBtn.style.display = (tab.is_builtin && tab.modified_from_bundled) ? '' : 'none';
        }

        try {
            const result = await API.get('/api/lua/' + encodeURIComponent(name));
            if (!result.ok) {
                if (editor) editor.value = '-- Ошибка: ' + (result.error || '?');
                return;
            }
            const text = result.content || '';
            if (editor) {
                editor.value = text;
                editor.disabled = false;
            }
            originalContent = text;
            setUnsaved(false);
            updateHighlight();
        } catch (err) {
            if (editor) editor.value = '-- Ошибка: ' + err.message;
        } finally {
            loading = false;
        }
    }

    function switchTab(name) {
        if (name === activeTab) return;

        if (hasUnsaved) {
            if (!confirm('Есть несохранённые изменения. Переключить таб?')) return;
        }

        activeTab = name;
        document.querySelectorAll('#lua-tabs .lists-tab').forEach(el => {
            el.classList.toggle('active', el.dataset.tab === name);
        });
        loadTab(name);
    }

    // ══════════════════ Editor / Highlight ══════════════════

    function onEditorInput() {
        if (loading) return;
        const editor = document.getElementById('lua-editor');
        if (!editor) return;
        setUnsaved(editor.value !== originalContent);
        // Сбрасываем результаты предыдущей проверки при ручном редактировании
        if (lastCheck) clearErrors();
        updateHighlight();
    }

    function onEditorKey(e) {
        const editor = e.target;
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = editor.selectionStart;
            const end = editor.selectionEnd;
            editor.value = editor.value.substring(0, start) + '    ' + editor.value.substring(end);
            editor.selectionStart = editor.selectionEnd = start + 4;
            onEditorInput();
        }
    }

    function syncScroll() {
        const editor = document.getElementById('lua-editor');
        const hl = document.getElementById('lua-highlight');
        const pre = hl ? hl.parentElement : null;
        const gutter = document.getElementById('lua-gutter');
        if (!editor) return;
        if (pre) {
            pre.scrollTop = editor.scrollTop;
            pre.scrollLeft = editor.scrollLeft;
        }
        if (gutter) gutter.scrollTop = editor.scrollTop;
    }

    function updateHighlight() {
        const editor = document.getElementById('lua-editor');
        const hl = document.getElementById('lua-highlight');
        const gutter = document.getElementById('lua-gutter');
        if (!editor || !hl) return;

        const src = editor.value;
        // Подсветка
        let html = (typeof LuaSyntax !== 'undefined' && LuaSyntax.highlight)
            ? LuaSyntax.highlight(src)
            : escapeHtml(src);

        // Подсветка строк с ошибками
        if (currentErrorLines.size > 0) {
            const lines = html.split('\n');
            for (const ln of currentErrorLines) {
                const idx = ln - 1;
                if (idx >= 0 && idx < lines.length) {
                    lines[idx] = '<span class="lua-line-error">' + lines[idx] + '​</span>';
                }
            }
            html = lines.join('\n');
        }

        // Завершающая пустая строка для корректного выравнивания
        if (src.endsWith('\n') || src === '') html += '\n';
        hl.innerHTML = html;

        // Gutter (номера строк)
        if (gutter) {
            const lineCount = Math.max(1, src.split('\n').length);
            // Кэшируем число строк, чтобы не дёргать DOM лишний раз
            if (gutter.dataset.lines !== String(lineCount)) {
                let g = '';
                for (let i = 1; i <= lineCount; i++) {
                    const cls = currentErrorLines.has(i) ? ' lua-gutter-err' : '';
                    g += '<span class="lua-gutter-line' + cls + '">' + i + '</span>\n';
                }
                gutter.innerHTML = g;
                gutter.dataset.lines = String(lineCount);
            } else if (currentErrorLines.size > 0) {
                // Обновим пометки об ошибках
                gutter.querySelectorAll('.lua-gutter-line').forEach((el, idx) => {
                    el.classList.toggle('lua-gutter-err', currentErrorLines.has(idx + 1));
                });
            }
        }

        syncScroll();
    }

    function setUnsaved(val) {
        hasUnsaved = val;
        const indicator = document.getElementById('lua-unsaved');
        const saveBtn = document.getElementById('lua-save-btn');
        if (indicator) indicator.style.display = val ? 'inline-flex' : 'none';
        if (saveBtn) saveBtn.disabled = !val;
    }

    // ══════════════════ Errors ══════════════════

    function clearErrors() {
        lastCheck = null;
        currentErrorLines = new Set();
        const panel = document.getElementById('lua-errors');
        if (panel) {
            panel.style.display = 'none';
            panel.innerHTML = '';
        }
        updateHighlight();
    }

    function showErrors(result) {
        lastCheck = result;
        currentErrorLines = new Set(
            (result.errors || []).map(e => e.line).filter(Boolean)
        );

        const panel = document.getElementById('lua-errors');
        if (!panel) return;

        const checker = result.checker || 'builtin';
        const checkerLabel = {
            'luac': 'luac (полная)',
            'lua': 'lua (loadstring)',
            'builtin': 'встроенная (без интерпретатора)',
        }[checker] || checker;

        if (result.valid) {
            panel.className = 'lua-errors lua-errors-ok';
            panel.style.display = 'block';
            panel.innerHTML = `
                <div class="lua-errors-head">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    <strong>Синтаксис корректен</strong>
                    <span class="lua-errors-checker">checker: ${escapeHtml(checkerLabel)}</span>
                </div>
                ${(result.warnings && result.warnings.length) ? `
                    <ul class="lua-errors-list">
                        ${result.warnings.map(w => `<li class="lua-warning">${escapeHtml(w)}</li>`).join('')}
                    </ul>
                ` : ''}
            `;
        } else {
            panel.className = 'lua-errors lua-errors-bad';
            panel.style.display = 'block';
            panel.innerHTML = `
                <div class="lua-errors-head">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <strong>Найдены ошибки: ${(result.errors || []).length}</strong>
                    <span class="lua-errors-checker">checker: ${escapeHtml(checkerLabel)}</span>
                </div>
                <ul class="lua-errors-list">
                    ${(result.errors || []).map(e => `
                        <li>
                            ${e.line ? `<a href="#" class="lua-err-line"
                                       onclick="LuaScriptsPage.gotoLine(${e.line}); return false;">строка ${e.line}</a>` : ''}
                            <span class="lua-err-msg">${escapeHtml(e.message || '')}</span>
                        </li>
                    `).join('')}
                </ul>
            `;
        }

        updateHighlight();
    }

    function gotoLine(line) {
        const editor = document.getElementById('lua-editor');
        if (!editor) return;
        const lines = editor.value.split('\n');
        let pos = 0;
        for (let i = 0; i < line - 1 && i < lines.length; i++) {
            pos += lines[i].length + 1;
        }
        editor.focus();
        editor.selectionStart = pos;
        editor.selectionEnd = pos + (lines[line - 1] || '').length;
        // Грубая прокрутка
        const lineH = parseFloat(getComputedStyle(editor).lineHeight) || 18;
        editor.scrollTop = Math.max(0, (line - 3) * lineH);
        syncScroll();
    }

    // ══════════════════ Actions ══════════════════

    async function checkSyntax() {
        const editor = document.getElementById('lua-editor');
        if (!editor) return;

        try {
            const result = await API.post('/api/lua/check', { content: editor.value });
            if (!result.ok) {
                Toast.error(result.error || 'Ошибка проверки');
                return;
            }
            showErrors(result);
            if (result.valid) {
                Toast.success('Синтаксис корректен (' + result.checker + ')');
            } else {
                Toast.error('Найдено ошибок: ' + (result.errors || []).length);
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function saveScript() {
        const editor = document.getElementById('lua-editor');
        if (!editor || !activeTab) return;

        try {
            const result = await API.put('/api/lua/' + encodeURIComponent(activeTab), {
                content: editor.value,
            });
            if (result.ok) {
                Toast.success(result.message || 'Сохранено');
                originalContent = editor.value;
                setUnsaved(false);
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function resetScript() {
        const tab = tabs.find(t => t.name === activeTab);
        if (!tab || !tab.is_builtin) return;
        if (!confirm('Восстановить ' + tab.label + ' из bundled? Текущее содержимое будет перезаписано.')) return;

        try {
            const result = await API.post('/api/lua/' + encodeURIComponent(activeTab) + '/reset');
            if (result.ok) {
                Toast.success(result.message || 'Сброшено');
                hasUnsaved = false;
                loadTab(activeTab);
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка сброса');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    async function deleteScript() {
        const tab = tabs.find(t => t.name === activeTab);
        if (!tab || tab.is_builtin) {
            Toast.warning('Нельзя удалить bundled-скрипт');
            return;
        }
        if (!confirm('Удалить скрипт ' + tab.label + '?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.delete('/api/lua/' + encodeURIComponent(activeTab));
            if (result.ok) {
                Toast.success(result.message || 'Удалено');
                activeTab = null;
                hasUnsaved = false;
                loadStats();
            } else {
                Toast.error(result.error || 'Ошибка удаления');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════════ Create modal ══════════════════

    function showCreateModal() {
        const modal = document.getElementById('lua-create-modal');
        const input = document.getElementById('lua-create-name');
        if (modal) modal.style.display = 'flex';
        if (input) {
            input.value = '';
            setTimeout(() => input.focus(), 50);
        }
    }

    function closeCreateModal() {
        const modal = document.getElementById('lua-create-modal');
        if (modal) modal.style.display = 'none';
    }

    async function createScript() {
        const input = document.getElementById('lua-create-name');
        if (!input) return;
        const name = input.value.trim();
        if (!name) {
            Toast.warning('Введите имя скрипта');
            return;
        }
        if (!/^[a-zA-Z0-9_.\-]{1,128}$/.test(name)) {
            Toast.error('Недопустимое имя. Разрешены латиница, цифры, "_", "-", "." (1..128)');
            return;
        }

        try {
            const result = await API.post('/api/lua/create', { name });
            if (result.ok) {
                Toast.success(result.message || 'Создано');
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

    // ══════════════════ Rename modal ══════════════════

    function showRenameModal() {
        const tab = tabs.find(t => t.name === activeTab);
        if (!tab || tab.is_builtin) {
            Toast.warning('Нельзя переименовать bundled-скрипт');
            return;
        }
        if (hasUnsaved && !confirm('Есть несохранённые изменения. Переименовать? Изменения будут потеряны.')) return;

        const modal = document.getElementById('lua-rename-modal');
        const oldInput = document.getElementById('lua-rename-old');
        const newInput = document.getElementById('lua-rename-new');
        if (oldInput) oldInput.value = activeTab;
        if (newInput) {
            newInput.value = activeTab;
            setTimeout(() => { newInput.focus(); newInput.select(); }, 50);
        }
        if (modal) modal.style.display = 'flex';
    }

    function closeRenameModal() {
        const modal = document.getElementById('lua-rename-modal');
        if (modal) modal.style.display = 'none';
    }

    async function renameScript() {
        const newInput = document.getElementById('lua-rename-new');
        if (!newInput) return;
        const newName = newInput.value.trim();
        if (!newName) { Toast.warning('Введите новое имя'); return; }
        if (newName === activeTab) { closeRenameModal(); return; }
        if (!/^[a-zA-Z0-9_.\-]{1,128}$/.test(newName)) {
            Toast.error('Недопустимое имя');
            return;
        }

        try {
            const result = await API.post('/api/lua/' + encodeURIComponent(activeTab) + '/rename', { new_name: newName });
            if (result.ok) {
                Toast.success(result.message || 'Переименовано');
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

    // ══════════════════ Utils ══════════════════

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function escapeAttr(text) {
        return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function formatBytes(n) {
        if (!n) return '0 B';
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        return (n / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function destroy() {
        hasUnsaved = false;
        loading = false;
        lastCheck = null;
        currentErrorLines = new Set();
    }

    return {
        render,
        destroy,
        switchTab,
        saveScript,
        resetScript,
        deleteScript,
        checkSyntax,
        gotoLine,
        showCreateModal,
        closeCreateModal,
        createScript,
        showRenameModal,
        closeRenameModal,
        renameScript,
    };
})();
