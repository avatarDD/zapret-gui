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

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">Стратегии</h1>
                    <p class="page-description">Управление стратегиями desync для nfqws2</p>
                </div>
                <button class="btn btn-primary" onclick="StrategiesPage.openCreate()">
                    <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                    </svg>
                    Создать стратегию
                </button>
            </div>

            <!-- Активная стратегия -->
            <div class="card" id="active-strategy-card" style="border-left: 3px solid var(--success);">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                    Активная стратегия
                </div>
                <div id="active-strategy-info" style="display:flex; align-items:center; gap:12px;">
                    <span class="text-muted">Загрузка...</span>
                </div>
            </div>

            <!-- Фильтры -->
            <div style="display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap;">
                <button class="btn btn-ghost btn-sm strat-filter active" data-filter="all" onclick="StrategiesPage.setFilter('all')">Все</button>
                <button class="btn btn-ghost btn-sm strat-filter" data-filter="favorites" onclick="StrategiesPage.setFilter('favorites')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                    </svg>
                    Избранные
                </button>
                <button class="btn btn-ghost btn-sm strat-filter" data-filter="builtin" onclick="StrategiesPage.setFilter('builtin')">Встроенные</button>
                <button class="btn btn-ghost btn-sm strat-filter" data-filter="user" onclick="StrategiesPage.setFilter('user')">Пользовательские</button>
            </div>

            <!-- Список стратегий -->
            <div id="strategies-list">
                <div class="text-muted" style="text-align:center; padding:32px;">
                    <div class="spinner" style="margin:0 auto 12px;"></div>
                    Загрузка стратегий...
                </div>
            </div>

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
                        <div class="log-viewer" id="preview-command" style="max-height:400px; white-space:pre-wrap; word-break:break-all; font-size:12px; line-height:1.6; padding:16px;">
                            Загрузка...
                        </div>
                        <div style="margin-top:12px; text-align:right;">
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
    }

    // ══════════════════ Data ══════════════════

    async function fetchStrategies() {
        try {
            const data = await API.get('/api/strategies');
            strategies = data.strategies || [];

            // Определяем активную
            const active = strategies.find(s => s.is_active);
            currentId = active ? active.id : null;
            favorites = strategies.filter(s => s.is_favorite).map(s => s.id);

            renderActiveCard(active);
            renderList(strategies);
        } catch (err) {
            document.getElementById('strategies-list').innerHTML =
                '<div class="card" style="text-align:center; padding:24px; color:var(--error);">Ошибка загрузки: ' + escapeHtml(err.message) + '</div>';
        }
    }

    // ══════════════════ Render List ══════════════════

    let currentFilter = 'all';

    function setFilter(filter) {
        currentFilter = filter;
        // Обновляем кнопки
        document.querySelectorAll('.strat-filter').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.filter === filter);
        });
        renderList(strategies);
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
        const container = document.getElementById('strategies-list');
        if (!container) return;

        // Фильтрация
        let filtered = list;
        if (currentFilter === 'favorites') {
            filtered = list.filter(s => s.is_favorite);
        } else if (currentFilter === 'builtin') {
            filtered = list.filter(s => s.is_builtin);
        } else if (currentFilter === 'user') {
            filtered = list.filter(s => !s.is_builtin);
        }

        if (filtered.length === 0) {
            const msgs = {
                all: 'Нет стратегий',
                favorites: 'Нет избранных стратегий',
                builtin: 'Нет встроенных стратегий',
                user: 'Нет пользовательских стратегий. Создайте первую!',
            };
            container.innerHTML = `<div class="card" style="text-align:center; padding:32px; color:var(--text-muted);">${msgs[currentFilter] || msgs.all}</div>`;
            return;
        }

        container.innerHTML = filtered.map(s => renderStrategyCard(s)).join('');
    }

    function renderStrategyCard(s) {
        const isActive = s.id === currentId;
        const isFav = s.is_favorite;
        const isBuiltin = s.is_builtin;
        const profileBadges = (s.profiles || []).map(p => {
            const enabled = p.enabled !== false;
            let color = 'var(--text-muted)';
            let label = p.name || p.id;
            if (label.toLowerCase().includes('http') && !label.toLowerCase().includes('https') && !label.toLowerCase().includes('tls')) color = 'var(--warning)';
            if (label.toLowerCase().includes('tls')) color = 'var(--success)';
            if (label.toLowerCase().includes('quic') || label.toLowerCase().includes('udp')) color = 'var(--info)';
            return `<span class="profile-badge${enabled ? '' : ' disabled'}" style="--badge-color:${color};">${escapeHtml(label)}</span>`;
        }).join('');

        return `
            <div class="strategy-card${isActive ? ' active' : ''}" data-id="${s.id}">
                <div class="strategy-card-header">
                    <div class="strategy-card-info">
                        <div class="strategy-card-name">
                            ${isActive ? '<span class="status-dot running" style="width:8px;height:8px;"></span>' : ''}
                            ${escapeHtml(s.name)}
                            ${isBuiltin ? '<span class="badge badge-muted">builtin</span>' : '<span class="badge badge-accent">user</span>'}
                        </div>
                        <div class="strategy-card-desc">${escapeHtml(s.description || '')}</div>
                    </div>
                    <button class="btn-icon-only fav-btn${isFav ? ' active' : ''}" onclick="StrategiesPage.toggleFavorite('${s.id}')" title="${isFav ? 'Убрать из избранного' : 'В избранное'}">
                        <svg viewBox="0 0 24 24" fill="${isFav ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                        </svg>
                    </button>
                </div>
                <div class="strategy-card-profiles">${profileBadges}</div>
                <div class="strategy-card-args-wrap">
                    ${(s.profiles || []).filter(p => p.enabled !== false).map(p => {
                        const args = p.args || '';
                        if (!args) return '';
                        return '<div class="strategy-args-preview">' + NfqwsSyntax.highlight(args) + '</div>';
                    }).join('')}
                </div>
                <div class="strategy-card-actions">
                    <button class="btn btn-primary btn-sm" onclick="StrategiesPage.applyStrategy('${s.id}')"${isActive ? ' disabled' : ''}>
                        ${isActive ? '✓ Активна' : 'Применить'}
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="StrategiesPage.showPreview('${s.id}')" title="Превью команды">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                        </svg>
                        Превью
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

        const modal = document.getElementById('strategy-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        if (!modal || !body) return;

        title.textContent = mode === 'create' ? 'Создать стратегию' : 'Редактировать стратегию';
        modal.style.display = 'flex';

        renderEditorForm(body);
        attachAutocompleteToProfiles();
    }

    function renderEditorForm(container) {
        const d = editorData;
        const isCreate = editorMode === 'create';

        container.innerHTML = `
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
                <div id="editor-preview-output" class="log-viewer" style="max-height:120px; margin-top:8px; display:none; white-space:pre-wrap; word-break:break-all; font-size:11px; padding:12px;"></div>
            </div>

            <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:20px; padding-top:16px; border-top:1px solid var(--border);">
                <button class="btn btn-ghost" onclick="StrategiesPage.closeModal()">Отмена</button>
                <button class="btn btn-primary" onclick="StrategiesPage.saveEditor()">
                    ${isCreate ? 'Создать' : 'Сохранить'}
                </button>
            </div>
        `;
    }

    function renderProfileEditor(profile, index) {
        const enabled = profile.enabled !== false;
        return `
            <div class="profile-editor-item" data-index="${index}">
                <div class="profile-editor-header">
                    <label class="toggle-label" style="flex:1; display:flex; align-items:center; gap:8px;">
                        <input type="checkbox" class="profile-toggle" ${enabled ? 'checked' : ''} onchange="StrategiesPage.toggleProfile(${index}, this.checked)">
                        <input type="text" class="form-input form-input-sm" value="${escapeHtml(profile.name || profile.id)}" placeholder="Имя профиля" onchange="StrategiesPage.updateProfileName(${index}, this.value)" style="flex:1; max-width:260px;">
                    </label>
                    <button class="btn-icon-only" onclick="StrategiesPage.removeProfile(${index})" title="Удалить профиль" style="color:var(--error); opacity:0.7;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="profile-args-wrap">
                    <textarea class="form-textarea profile-args" rows="3" placeholder="--filter-tcp=443 --filter-l7=tls ..." onchange="StrategiesPage.updateProfileArgs(${index}, this.value)">${escapeHtml(profile.args || '')}</textarea>
                    <span class="profile-args-hint">Ctrl+Space</span>
                </div>
            </div>
        `;
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
                closeModal();
                fetchStrategies();
            } else {
                Toast.error(result.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function attachAutocompleteToProfiles() {
        // Detach old instances first
        NfqwsAutocomplete.detachAll();
        // Pre-load file lists for suggestions
        NfqwsAutocomplete.loadFiles();
        // Attach to all profile textareas (async to ensure DOM is ready)
        setTimeout(() => {
            const textareas = document.querySelectorAll('.profile-args');
            textareas.forEach(ta => NfqwsAutocomplete.attach(ta));
        }, 0);
    }

    function closeModal() {
        NfqwsAutocomplete.detachAll();
        const modal = document.getElementById('strategy-modal');
        if (modal) modal.style.display = 'none';
        editorData = null;
    }

    // ══════════════════ Utils ══════════════════

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function destroy() {
        NfqwsAutocomplete.detachAll();
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
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
        editorPreview,
        saveEditor,
    };
})();
