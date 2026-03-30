const BlobsPage = (() => {
    let blobs = [];
    let stats = {};
    function render(container) {
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="22" height="22">
                            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                        </svg>
                        Блобы
                    </h1>
                    <p class="page-description">Бинарные данные для fake-пакетов nfqws2</p>
                </div>
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-ghost" onclick="BlobsPage.openGenerate()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                        </svg>
                        Сгенерировать
                    </button>
                    <button class="btn btn-primary" onclick="BlobsPage.openCreate()">
                        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                        </svg>
                        Создать блоб
                    </button>
                </div>
            </div>
            <!-- Статистика -->
            <div class="status-grid" id="blob-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>
            <!-- Таблица блобов -->
            <div class="card" id="blobs-list-card">
                <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                    <span>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="vertical-align: -2px;">
                            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                        </svg>
                        Все блобы
                    </span>
                    <button class="btn btn-ghost btn-sm" onclick="BlobsPage.refresh()" title="Обновить">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="23 4 23 10 17 10"/>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                        </svg>
                    </button>
                </div>
                <div id="blobs-table-wrap">
                    <div class="text-muted" style="text-align:center; padding:32px;">
                        <div class="spinner" style="margin:0 auto 12px;"></div>
                        Загрузка блобов...
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
                    Как использовать блобы
                </div>
                <div style="font-size:12px; color:var(--text-secondary); line-height:1.7;">
                    В стратегиях блобы указываются параметром:
                    <code style="background:var(--bg-input); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">
                        --lua-desync=fake:blob=&lt;имя_блоба&gt;
                    </code><br>
                    Блобы с префиксом <strong>fake_default_</strong> — встроенные и не могут быть удалены.<br>
                    Генератор создаёт fake TLS ClientHello или HTTP GET для указанного домена.
                </div>
            </div>
            <!-- Модал: просмотр блоба -->
            <div id="blob-view-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title" id="blob-view-title">Просмотр блоба</h3>
                        <button class="modal-close" onclick="BlobsPage.closeView()">&times;</button>
                    </div>
                    <div class="modal-body" id="blob-view-body">
                        <div class="text-muted" style="text-align:center; padding:24px;">Загрузка...</div>
                    </div>
                </div>
            </div>
            <!-- Модал: создать блоб -->
            <div id="blob-create-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title">Создать блоб</h3>
                        <button class="modal-close" onclick="BlobsPage.closeCreate()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Имя блоба</label>
                            <input type="text" class="form-input" id="blob-create-name"
                                   placeholder="my_custom_blob" spellcheck="false"
                                   style="font-family:var(--font-mono);">
                            <span class="form-hint">Допустимы: латиница, цифры, _ - .</span>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Hex-данные</label>
                            <textarea class="form-textarea" id="blob-create-hex"
                                      placeholder="16 03 01 00 f1 01 00 00 ed 03 03..."
                                      spellcheck="false"
                                      style="font-family:var(--font-mono); font-size:12px; min-height:160px; resize:vertical;"></textarea>
                            <span class="form-hint">Форматы: "16 03 01", "160301", "16:03:01", "0x16 0x03"</span>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="BlobsPage.closeCreate()">Отмена</button>
                            <button class="btn btn-primary" id="blob-create-btn" onclick="BlobsPage.doCreate()">
                                Создать
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Модал: генератор -->
            <div id="blob-gen-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title">Генератор fake-блоба</h3>
                        <button class="modal-close" onclick="BlobsPage.closeGenerate()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div style="display:flex; gap:12px; flex-wrap:wrap;">
                            <div class="form-group" style="flex:1; min-width:200px;">
                                <label class="form-label">Тип пакета</label>
                                <select class="form-input" id="blob-gen-type">
                                    <option value="tls">TLS ClientHello</option>
                                    <option value="http">HTTP GET</option>
                                </select>
                            </div>
                            <div class="form-group" style="flex:2; min-width:200px;">
                                <label class="form-label">Домен</label>
                                <input type="text" class="form-input" id="blob-gen-domain"
                                       placeholder="youtube.com" spellcheck="false">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Имя для сохранения (опционально)</label>
                            <input type="text" class="form-input" id="blob-gen-name"
                                   placeholder="fake_tls_youtube" spellcheck="false"
                                   style="font-family:var(--font-mono);">
                            <span class="form-hint">Если указано — блоб будет сохранён. Иначе — только превью.</span>
                        </div>
                        <div class="asn-presets" style="margin-bottom:12px;">
                            <span class="form-hint">Быстрый выбор:</span>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('youtube.com')">YouTube</button>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('discord.com')">Discord</button>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('t.me')">Telegram</button>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('instagram.com')">Instagram</button>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('x.com')">X/Twitter</button>
                            <button class="btn-chip" onclick="BlobsPage.setGenDomain('chatgpt.com')">ChatGPT</button>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end;">
                            <button class="btn btn-ghost" onclick="BlobsPage.closeGenerate()">Отмена</button>
                            <button class="btn btn-primary" id="blob-gen-btn" onclick="BlobsPage.doGenerate()">
                                <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                                </svg>
                                Сгенерировать
                            </button>
                        </div>
                        <!-- Результат генерации -->
                        <div id="blob-gen-result" style="display:none; margin-top:16px;">
                            <div class="form-label" style="margin-bottom:6px;">Результат</div>
                            <div id="blob-gen-result-info" style="font-size:12px; color:var(--text-secondary); margin-bottom:8px;"></div>
                            <div class="blob-hex-viewer" id="blob-gen-hex-dump"
                                 style="background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px; font-family:var(--font-mono); font-size:11px; line-height:1.6; max-height:250px; overflow:auto; white-space:pre; color:var(--text-secondary);">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Модал: редактирование hex -->
            <div id="blob-edit-modal" class="modal-backdrop" style="display:none;">
                <div class="modal-content modal-lg">
                    <div class="modal-header">
                        <h3 class="modal-title" id="blob-edit-title">Редактировать блоб</h3>
                        <button class="modal-close" onclick="BlobsPage.closeEdit()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label class="form-label">Hex-данные</label>
                            <textarea class="form-textarea" id="blob-edit-hex"
                                      spellcheck="false"
                                      style="font-family:var(--font-mono); font-size:12px; min-height:200px; resize:vertical;"></textarea>
                            <span class="form-hint">Редактируйте hex-данные. Пробелы, двоеточия, переносы допустимы.</span>
                        </div>
                        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:16px;">
                            <button class="btn btn-ghost" onclick="BlobsPage.closeEdit()">Отмена</button>
                            <button class="btn btn-primary" id="blob-edit-btn" onclick="BlobsPage.doEdit()">
                                Сохранить
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        loadData();
    }
    async function loadData() {
        await Promise.all([loadBlobs(), loadStats()]);
    }
    async function loadBlobs() {
        try {
            const data = await API.get('/api/blobs');
            blobs = data.blobs || [];
            renderTable(blobs);
        } catch (err) {
            document.getElementById('blobs-table-wrap').innerHTML =
                '<div style="text-align:center; padding:24px; color:var(--error);">Ошибка загрузки: ' + escapeHtml(err.message) + '</div>';
        }
    }
    async function loadStats() {
        try {
            const data = await API.get('/api/blobs/stats');
            stats = data.stats || {};
            renderStats(stats);
        } catch (err) {
        }
    }
    function renderStats(s) {
        const grid = document.getElementById('blob-stats-grid');
        if (!grid) return;
        grid.innerHTML = `
            <div class="status-card">
                <div class="status-card-header">
                    <span class="status-card-icon" style="color:var(--accent);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                        </svg>
                    </span>
                    <span class="status-card-label">Всего</span>
                </div>
                <div class="status-card-value">${s.total || 0}</div>
                <div class="status-card-detail">блобов</div>
            </div>
            <div class="status-card">
                <div class="status-card-header">
                    <span class="status-card-icon" style="color:var(--warning);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                    </span>
                    <span class="status-card-label">Встроенные</span>
                </div>
                <div class="status-card-value">${s.builtin || 0}</div>
                <div class="status-card-detail">builtin</div>
            </div>
            <div class="status-card">
                <div class="status-card-header">
                    <span class="status-card-icon" style="color:var(--success);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                            <circle cx="8.5" cy="7" r="4"/>
                            <line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/>
                        </svg>
                    </span>
                    <span class="status-card-label">Пользовательские</span>
                </div>
                <div class="status-card-value">${s.user || 0}</div>
                <div class="status-card-detail">user</div>
            </div>
            <div class="status-card">
                <div class="status-card-header">
                    <span class="status-card-icon" style="color:var(--info);">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                    </span>
                    <span class="status-card-label">Общий размер</span>
                </div>
                <div class="status-card-value">${formatSize(s.total_size || 0)}</div>
                <div class="status-card-detail">${s.total_size || 0} байт</div>
            </div>
        `;
    }
    function renderTable(list) {
        const wrap = document.getElementById('blobs-table-wrap');
        if (!wrap) return;
        if (list.length === 0) {
            wrap.innerHTML = `
                <div style="text-align:center; padding:40px 20px; color:var(--text-muted);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                         width="40" height="40" style="margin-bottom:12px; opacity:0.5;">
                        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                    </svg>
                    <div style="font-size:14px; font-weight:500; margin-bottom:4px;">Нет блобов</div>
                    <div style="font-size:12px;">Создайте блоб или сгенерируйте fake-пакет</div>
                </div>
            `;
            return;
        }
        let html = '<div class="blob-table">';
        html += `
            <div class="blob-table-header">
                <div class="blob-col-name">Имя</div>
                <div class="blob-col-type">Тип</div>
                <div class="blob-col-size">Размер</div>
                <div class="blob-col-badge">Статус</div>
                <div class="blob-col-actions">Действия</div>
            </div>
        `;
        for (const b of list) {
            const typeIcon = getTypeIcon(b.type);
            const typeLabel = getTypeLabel(b.type);
            const badgeClass = b.is_builtin ? 'blob-badge-builtin' : 'blob-badge-user';
            const badgeText = b.is_builtin ? 'builtin' : 'user';
            html += `
                <div class="blob-table-row">
                    <div class="blob-col-name" title="${escapeHtml(b.name)}">
                        <span class="blob-name-icon">${typeIcon}</span>
                        <span class="blob-name-text">${escapeHtml(b.name)}</span>
                    </div>
                    <div class="blob-col-type">
                        <span class="blob-type-label">${typeLabel}</span>
                    </div>
                    <div class="blob-col-size">${formatSize(b.size)}</div>
                    <div class="blob-col-badge">
                        <span class="blob-badge ${badgeClass}">${badgeText}</span>
                    </div>
                    <div class="blob-col-actions">
                        <button class="btn btn-ghost btn-sm" onclick="BlobsPage.viewBlob('${escapeHtml(b.name)}')" title="Просмотр hex">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="BlobsPage.editBlob('${escapeHtml(b.name)}')" title="Редактировать">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                        ${!b.is_builtin ? `
                            <button class="btn btn-ghost btn-sm" onclick="BlobsPage.deleteBlob('${escapeHtml(b.name)}')" title="Удалить" style="color:var(--error);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                            </button>
                        ` : `
                            <button class="btn btn-ghost btn-sm" disabled title="Встроенный блоб нельзя удалить" style="opacity:0.3;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                                </svg>
                            </button>
                        `}
                    </div>
                </div>
            `;
        }
        html += '</div>';
        wrap.innerHTML = html;
    }
    async function viewBlob(name) {
        const modal = document.getElementById('blob-view-modal');
        const title = document.getElementById('blob-view-title');
        const body = document.getElementById('blob-view-body');
        if (!modal || !body) return;
        title.textContent = 'Блоб: ' + name;
        body.innerHTML = '<div class="text-muted" style="text-align:center; padding:24px;"><div class="spinner" style="margin:0 auto 12px;"></div>Загрузка...</div>';
        modal.style.display = 'flex';
        try {
            const data = await API.get('/api/blobs/' + encodeURIComponent(name));
            const blob = data.blob;
            body.innerHTML = `
                <div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:16px;">
                    <div style="flex:1; min-width:120px;">
                        <div class="form-hint" style="margin-bottom:2px;">Тип</div>
                        <div style="font-weight:500;">${getTypeLabel(blob.type)}</div>
                    </div>
                    <div style="flex:1; min-width:120px;">
                        <div class="form-hint" style="margin-bottom:2px;">Размер</div>
                        <div style="font-weight:500;">${blob.size} байт (${formatSize(blob.size)})</div>
                    </div>
                    <div style="flex:1; min-width:120px;">
                        <div class="form-hint" style="margin-bottom:2px;">Статус</div>
                        <div><span class="blob-badge ${blob.is_builtin ? 'blob-badge-builtin' : 'blob-badge-user'}">${blob.is_builtin ? 'builtin' : 'user'}</span></div>
                    </div>
                </div>
                <div class="form-group">
                    <div class="form-label" style="display:flex; justify-content:space-between; align-items:center;">
                        <span>Hex-дамп</span>
                        <button class="btn btn-ghost btn-sm" onclick="BlobsPage.copyHex('view')" title="Копировать hex">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                            Копировать
                        </button>
                    </div>
                    <div class="blob-hex-viewer" id="blob-view-hexdump"
                         style="background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px; font-family:var(--font-mono); font-size:11px; line-height:1.6; max-height:350px; overflow:auto; white-space:pre; color:var(--text-secondary);">${escapeHtml(blob.hex_dump || '')}</div>
                </div>
                <div class="form-group">
                    <div class="form-label">Raw hex</div>
                    <textarea class="form-textarea" id="blob-view-hex" readonly
                              style="font-family:var(--font-mono); font-size:11px; min-height:60px; resize:vertical; color:var(--text-muted);">${escapeHtml(blob.hex || '')}</textarea>
                </div>
            `;
        } catch (err) {
            body.innerHTML = '<div style="text-align:center; padding:24px; color:var(--error);">Ошибка: ' + escapeHtml(err.message) + '</div>';
        }
    }
    function closeView() {
        const modal = document.getElementById('blob-view-modal');
        if (modal) modal.style.display = 'none';
    }
    function openCreate() {
        const modal = document.getElementById('blob-create-modal');
        if (modal) {
            document.getElementById('blob-create-name').value = '';
            document.getElementById('blob-create-hex').value = '';
            modal.style.display = 'flex';
            document.getElementById('blob-create-name').focus();
        }
    }
    function closeCreate() {
        const modal = document.getElementById('blob-create-modal');
        if (modal) modal.style.display = 'none';
    }
    async function doCreate() {
        const name = document.getElementById('blob-create-name').value.trim();
        const hex = document.getElementById('blob-create-hex').value.trim();
        const btn = document.getElementById('blob-create-btn');
        if (!name) {
            Toast.warning('Укажите имя блоба');
            return;
        }
        if (!hex) {
            Toast.warning('Введите hex-данные');
            return;
        }
        btn.disabled = true;
        btn.textContent = 'Создание...';
        try {
            await API.post('/api/blobs', { name, hex });
            Toast.success('Блоб создан: ' + name);
            closeCreate();
            loadData();
        } catch (err) {
            Toast.error(err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Создать';
        }
    }
    let editingBlobName = '';
    async function editBlob(name) {
        editingBlobName = name;
        const modal = document.getElementById('blob-edit-modal');
        const title = document.getElementById('blob-edit-title');
        const textarea = document.getElementById('blob-edit-hex');
        if (!modal || !textarea) return;
        title.textContent = 'Редактировать: ' + name;
        textarea.value = 'Загрузка...';
        textarea.disabled = true;
        modal.style.display = 'flex';
        try {
            const data = await API.get('/api/blobs/' + encodeURIComponent(name));
            textarea.value = data.blob.hex || '';
            textarea.disabled = false;
        } catch (err) {
            Toast.error('Ошибка загрузки: ' + err.message);
            textarea.value = '';
            textarea.disabled = false;
        }
    }
    function closeEdit() {
        const modal = document.getElementById('blob-edit-modal');
        if (modal) modal.style.display = 'none';
        editingBlobName = '';
    }
    async function doEdit() {
        if (!editingBlobName) return;
        const hex = document.getElementById('blob-edit-hex').value.trim();
        const btn = document.getElementById('blob-edit-btn');
        if (!hex) {
            Toast.warning('Hex-данные не могут быть пустыми');
            return;
        }
        btn.disabled = true;
        btn.textContent = 'Сохранение...';
        try {
            await API.put('/api/blobs/' + encodeURIComponent(editingBlobName), { hex });
            Toast.success('Блоб обновлён: ' + editingBlobName);
            closeEdit();
            loadData();
        } catch (err) {
            Toast.error(err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Сохранить';
        }
    }
    async function deleteBlob(name) {
        if (!confirm('Удалить блоб "' + name + '"?')) return;
        try {
            await API.delete('/api/blobs/' + encodeURIComponent(name));
            Toast.success('Блоб удалён: ' + name);
            loadData();
        } catch (err) {
            Toast.error(err.message);
        }
    }
    function openGenerate() {
        const modal = document.getElementById('blob-gen-modal');
        if (modal) {
            document.getElementById('blob-gen-type').value = 'tls';
            document.getElementById('blob-gen-domain').value = '';
            document.getElementById('blob-gen-name').value = '';
            document.getElementById('blob-gen-result').style.display = 'none';
            modal.style.display = 'flex';
            document.getElementById('blob-gen-domain').focus();
        }
    }
    function closeGenerate() {
        const modal = document.getElementById('blob-gen-modal');
        if (modal) modal.style.display = 'none';
    }
    function setGenDomain(domain) {
        const input = document.getElementById('blob-gen-domain');
        if (input) input.value = domain;
        const nameInput = document.getElementById('blob-gen-name');
        const typeSelect = document.getElementById('blob-gen-type');
        if (nameInput && typeSelect) {
            const safeDomain = domain.replace(/\./g, '_');
            nameInput.value = 'fake_' + typeSelect.value + '_' + safeDomain;
        }
    }
    async function doGenerate() {
        const type = document.getElementById('blob-gen-type').value;
        const domain = document.getElementById('blob-gen-domain').value.trim();
        const name = document.getElementById('blob-gen-name').value.trim();
        const btn = document.getElementById('blob-gen-btn');
        const resultDiv = document.getElementById('blob-gen-result');
        if (!domain) {
            Toast.warning('Укажите домен');
            return;
        }
        btn.disabled = true;
        try {
            const body = { type, domain };
            if (name) body.name = name;
            const data = await API.post('/api/blobs/generate', body);
            const gen = data.generated;
            document.getElementById('blob-gen-result-info').innerHTML =
                `Тип: <strong>${escapeHtml(gen.type.toUpperCase())}</strong> | ` +
                `Домен: <strong>${escapeHtml(gen.domain)}</strong> | ` +
                `Размер: <strong>${gen.size} байт</strong>` +
                (data.saved ? ` | Сохранён как: <strong>${escapeHtml(data.saved.name)}</strong>` : '');
            document.getElementById('blob-gen-hex-dump').textContent = gen.hex_dump || gen.hex;
            resultDiv.style.display = 'block';
            if (data.saved) {
                Toast.success('Блоб сгенерирован и сохранён: ' + data.saved.name);
                loadData();
            } else {
                Toast.success('Fake-пакет сгенерирован (' + gen.size + ' байт)');
            }
        } catch (err) {
            Toast.error(err.message);
        } finally {
            btn.disabled = false;
        }
    }
    function copyHex(source) {
        let text = '';
        if (source === 'view') {
            const el = document.getElementById('blob-view-hex');
            text = el ? el.value : '';
        }
        if (text) {
            navigator.clipboard.writeText(text).then(() => {
                Toast.success('Hex скопирован в буфер обмена');
            }).catch(() => {
                Toast.error('Не удалось скопировать');
            });
        }
    }
    // ══════════════════ Refresh ══════════════════
    function refresh() {
        loadData();
        Toast.info('Обновлено');
    }
    // ══════════════════ Utilities ══════════════════
    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }
    function getTypeIcon(type) {
        switch (type) {
            case 'tls':
                return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--success);"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
            case 'http':
                return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--info);"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>';
            case 'quic':
                return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--warning);"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>';
            default:
                return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="color:var(--text-muted);"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
        }
    }
    function getTypeLabel(type) {
        switch (type) {
            case 'tls':  return 'TLS';
            case 'http': return 'HTTP';
            case 'quic': return 'QUIC';
            default:     return 'unknown';
        }
    }
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    function destroy() {
    }
    return {
        render,
        destroy,
        refresh,
        viewBlob,
        closeView,
        openCreate,
        closeCreate,
        doCreate,
        editBlob,
        closeEdit,
        doEdit,
        deleteBlob,
        openGenerate,
        closeGenerate,
        setGenDomain,
        doGenerate,
        copyHex,
    };
})();
