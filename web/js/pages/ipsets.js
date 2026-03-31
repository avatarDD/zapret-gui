/**
 * ipsets.js — Страница управления IP-списками.
 *
 * Табы: ipset-base.txt | my-ipset.txt
 * Функции: просмотр, редактирование, добавление IP/CIDR,
 *          загрузка по ASN через RIPE API, сброс к дефолтам.
 */

const IPSetsPage = (() => {

    const TABS = [
        { name: 'ipset-base', label: 'ipset-base.txt', desc: 'Базовые IP-адреса и подсети' },
        { name: 'my-ipset',   label: 'my-ipset.txt',   desc: 'Пользовательские IP/подсети' },
    ];

    let activeTab = 'ipset-base';
    let originalContent = '';
    let hasUnsaved = false;
    let loading = false;

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
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

            <!-- Статистика -->
            <div class="status-grid" id="ip-stats-grid">
                <div class="status-card"><div class="status-card-label">Загрузка...</div></div>
            </div>

            <!-- Табы -->
            <div class="card" style="padding: 0;">
                <div class="lists-tabs" id="ip-tabs">
                    ${TABS.map(t => `
                        <button class="lists-tab ${t.name === activeTab ? 'active' : ''}"
                                data-tab="${t.name}"
                                onclick="IPSetsPage.switchTab('${t.name}')">
                            <span class="lists-tab-name">${t.label}</span>
                            <span class="lists-tab-count" id="ip-tab-count-${t.name}">—</span>
                        </button>
                    `).join('')}
                </div>

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
                            <select class="form-input" id="ip-asn-target" style="max-width:160px;">
                                <option value="ipset-base">ipset-base.txt</option>
                                <option value="my-ipset" selected>my-ipset.txt</option>
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
        `;

        // Загружаем данные
        loadStats();
        loadTab(activeTab);

        // Слушаем изменения
        const editor = document.getElementById('ip-editor');
        if (editor) {
            editor.addEventListener('input', onEditorInput);
        }
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadStats() {
        try {
            const result = await API.get('/api/ipsets');
            if (!result.ok) return;

            const grid = document.getElementById('ip-stats-grid');
            if (!grid) return;

            grid.innerHTML = result.files.map(f => `
                <div class="status-card" style="cursor:pointer;" onclick="IPSetsPage.switchTab('${f.name}')">
                    <div class="status-card-header">
                        <svg class="status-card-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                        </svg>
                        <span class="status-card-label">${f.filename}</span>
                    </div>
                    <div class="status-card-value">${f.count}</div>
                    <div class="status-card-detail">${f.description}</div>
                </div>
            `).join('');

            // Обновляем счётчики
            result.files.forEach(f => {
                const cnt = document.getElementById('ip-tab-count-' + f.name);
                if (cnt) cnt.textContent = f.count;
            });
        } catch (err) {
            console.error('loadStats error:', err);
        }
    }

    async function loadTab(name) {
        loading = true;
        const editor = document.getElementById('ip-editor');
        const desc = document.getElementById('ip-tab-desc');

        if (editor) editor.value = 'Загрузка...';
        if (editor) editor.disabled = true;

        const tab = TABS.find(t => t.name === name);
        if (desc && tab) desc.textContent = tab.desc;

        try {
            const result = await API.get('/api/ipsets/' + name);
            if (!result.ok) {
                if (editor) editor.value = 'Ошибка: ' + (result.error || '?');
                return;
            }

            const text = result.entries.join('\n');
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
            const result = await API.put('/api/ipsets/' + activeTab, { entries });
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
            const result = await API.post('/api/ipsets/' + activeTab + '/reset');
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

                // Перезагружаем если целевой таб активен
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
        setASN,
        loadASN,
    };
})();
