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

            <!-- Список стратегий (ListUI рендерит свой поиск/фильтры/пагинацию) -->
            <div id="strategies-list-host">
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
        // Если пришли сюда из blockcheck2-бейджа — открыть редактор с приёмом.
        consumePendingPrefill();
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

            renderActiveCard(active);
            renderList(strategies);
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
            <div class="strategy-card compact${isActive ? ' active' : ''}" data-id="${s.id}" data-list-ui-card>
                <div class="strategy-card-header">
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

        const modal = document.getElementById('strategy-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');
        if (!modal || !body) return;

        title.textContent = mode === 'create' ? 'Создать стратегию' : 'Редактировать стратегию';
        modal.style.display = 'flex';

        // Грузим список hostlist-файлов и перерисовываем форму, чтобы дропдаун был актуален
        renderEditorForm(body);
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
                <div class="profile-args-wrap">
                    <textarea class="form-textarea profile-args" rows="3" placeholder="--filter-tcp=443 --filter-l7=tls ..." onchange="StrategiesPage.updateProfileArgs(${index}, this.value)">${escapeHtml(profile.args || '')}</textarea>
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

    function renderProfileHint(args) {
        const h = profileHint(args);
        if (!h) return '';
        const icon = h.level === 'warn' ? '⚠' : 'ℹ';
        return `<span class="profile-hint-${h.level}">${icon} ${escapeHtml(h.text)}</span>`;
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
        updateProfileHintEl(index);
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
        if (catalogPollTimer) {
            clearInterval(catalogPollTimer);
            catalogPollTimer = null;
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
        prefillCreate,
        editorPreview,
        saveEditor,
        updateCatalog,
    };
})();
