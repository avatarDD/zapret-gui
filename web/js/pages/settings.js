/**
 * settings.js — Страница настроек.
 *
 * Возможности:
 *   - Просмотр и редактирование конфигурации (пути, порты, интерфейсы)
 *   - Секции: Zapret2, Web-GUI, nfqws, Firewall, Фильтрация, Логирование, Интерфейсы
 *   - Импорт/экспорт конфигурации (JSON)
 *   - Сброс к настройкам по умолчанию
 *   - Информация о версии и системе
 */

const SettingsPage = (() => {
    // ══════════════════ State ══════════════════

    let config = {};
    let originalConfig = {};
    let hasUnsaved = false;
    let loading = false;
    let activeSection = 'zapret';
    let systemInfo = null;

    const GUI_VERSION = 'v0.11.0';

    // Определения секций конфигурации
    const SECTIONS = [
        {
            id: 'zapret',
            label: 'Zapret2',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
            fields: [
                { key: 'zapret.base_path',     label: 'Базовый путь zapret2',   type: 'text', placeholder: '/opt/zapret2' },
                { key: 'zapret.nfqws_binary',  label: 'Путь к nfqws2',          type: 'text', placeholder: '/opt/zapret2/nfq2/nfqws2' },
                { key: 'zapret.lua_path',      label: 'Путь к Lua-скриптам',    type: 'text', placeholder: '/opt/zapret2/lua' },
                { key: 'zapret.lists_path',    label: 'Путь к спискам',         type: 'text', placeholder: '/opt/zapret2/lists' },
                { key: 'zapret.config_path',   label: 'Путь к конфигурации',    type: 'text', placeholder: '/opt/zapret2/config' },
            ]
        },
        {
            id: 'gui',
            label: 'Web-GUI',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
            fields: [
                { key: 'gui.host',            label: 'Адрес привязки',    type: 'text',   placeholder: '0.0.0.0' },
                { key: 'gui.port',            label: 'Порт',              type: 'number', placeholder: '8080', min: 1, max: 65535 },
                { key: 'gui.debug',           label: 'Режим отладки',     type: 'toggle' },
                { key: 'gui.auth_enabled',    label: 'Авторизация',       type: 'toggle' },
                { key: 'gui.auth_user',       label: 'Логин',             type: 'text',   placeholder: 'admin', showIf: 'gui.auth_enabled' },
                { key: 'gui.auth_password',   label: 'Пароль',            type: 'password', placeholder: '••••••', showIf: 'gui.auth_enabled' },
            ]
        },
        {
            id: 'nfqws',
            label: 'nfqws',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
            fields: [
                { key: 'nfqws.queue_num',          label: 'Номер очереди NFQUEUE',  type: 'number', min: 0, max: 65535 },
                { key: 'nfqws.ports_tcp',           label: 'TCP-порты',              type: 'text', placeholder: '80,443' },
                { key: 'nfqws.ports_udp',           label: 'UDP-порты',              type: 'text', placeholder: '443' },
                { key: 'nfqws.tcp_pkt_out',         label: 'TCP пакетов OUT',        type: 'number', min: 1, max: 100 },
                { key: 'nfqws.tcp_pkt_in',          label: 'TCP пакетов IN',         type: 'number', min: 0, max: 100 },
                { key: 'nfqws.udp_pkt_out',         label: 'UDP пакетов OUT',        type: 'number', min: 1, max: 100 },
                { key: 'nfqws.udp_pkt_in',          label: 'UDP пакетов IN',         type: 'number', min: 0, max: 100 },
                { key: 'nfqws.desync_mark',         label: 'Desync mark',            type: 'text', placeholder: '0x40000000' },
                { key: 'nfqws.desync_mark_postnat',  label: 'Desync mark (postnat)',  type: 'text', placeholder: '0x20000000' },
                { key: 'nfqws.user',                label: 'Пользователь',           type: 'text', placeholder: 'nobody' },
                { key: 'nfqws.disable_ipv6',        label: 'Отключить IPv6',         type: 'toggle' },
            ]
        },
        {
            id: 'firewall',
            label: 'Firewall',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
            fields: [
                { key: 'firewall.type',            label: 'Тип firewall',    type: 'select', options: [
                    { value: 'auto', label: 'Авто' }, { value: 'iptables', label: 'iptables' }, { value: 'nftables', label: 'nftables' }
                ]},
                { key: 'firewall.apply_on_start',  label: 'Применять правила при старте', type: 'toggle' },
                { key: 'firewall.flowoffload',     label: 'Flow Offload',    type: 'select', options: [
                    { value: 'donttouch', label: 'Не трогать' }, { value: 'none', label: 'Выключить' },
                    { value: 'software', label: 'Software' }, { value: 'hardware', label: 'Hardware' },
                ]},
                { key: 'firewall.postnat',         label: 'Post-NAT',        type: 'toggle' },
            ]
        },
        {
            id: 'filter',
            label: 'Фильтрация',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
            fields: [
                { key: 'filter.mode',  label: 'Режим фильтрации',  type: 'select', options: [
                    { value: 'none', label: 'Без фильтрации' },
                    { value: 'ipset', label: 'По IP-списку' },
                    { value: 'hostlist', label: 'По хостлисту' },
                    { value: 'autohostlist', label: 'Авто-хостлист' },
                ]},
            ]
        },
        {
            id: 'logging',
            label: 'Логирование',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            fields: [
                { key: 'logging.max_entries',  label: 'Макс. записей в буфере',  type: 'number', min: 100, max: 10000 },
                { key: 'logging.file_enabled', label: 'Запись в файл',            type: 'toggle' },
                { key: 'logging.file_path',    label: 'Путь к файлу логов',       type: 'text', placeholder: '/tmp/zapret-gui.log', showIf: 'logging.file_enabled' },
                { key: 'logging.level',        label: 'Уровень логирования',      type: 'select', options: [
                    { value: 'DEBUG', label: 'DEBUG' }, { value: 'INFO', label: 'INFO' },
                    { value: 'WARNING', label: 'WARNING' }, { value: 'ERROR', label: 'ERROR' },
                ]},
            ]
        },
        {
            id: 'interfaces',
            label: 'Интерфейсы',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
            fields: [
                { key: 'interfaces.wan',   label: 'WAN интерфейс',   type: 'text', placeholder: 'Авто (пусто)' },
                { key: 'interfaces.wan6',  label: 'WAN6 интерфейс',  type: 'text', placeholder: 'Авто (пусто)' },
                { key: 'interfaces.lan',   label: 'LAN интерфейс',   type: 'text', placeholder: 'Авто (пусто)' },
            ]
        },
    ];

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Настройки</h1>
                    <p class="page-description">Конфигурация Web-GUI и параметры nfqws2</p>
                </div>
                <div class="settings-header-actions">
                    <button class="btn btn-ghost btn-sm" onclick="SettingsPage.exportConfig()" title="Экспортировать конфигурацию">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/>
                            <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                        <span class="btn-label-desktop">Экспорт</span>
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SettingsPage.importConfig()" title="Импортировать конфигурацию">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        <span class="btn-label-desktop">Импорт</span>
                    </button>
                </div>
            </div>

            <div class="settings-layout">
                <!-- Навигация по секциям -->
                <div class="settings-nav card" id="settings-nav">
                    ${renderSectionNav()}
                </div>

                <!-- Содержимое секции -->
                <div class="settings-content" id="settings-content">
                    <div class="card settings-section-card" id="settings-form">
                        <div class="settings-loading">
                            <div class="spinner"></div>
                            <span>Загрузка...</span>
                        </div>
                    </div>

                    <!-- Unsaved changes bar -->
                    <div class="settings-save-bar hidden" id="settings-save-bar">
                        <span class="settings-save-text">Есть несохранённые изменения</span>
                        <div class="settings-save-btns">
                            <button class="btn btn-ghost btn-sm" onclick="SettingsPage.discardChanges()">Отменить</button>
                            <button class="btn btn-success btn-sm" onclick="SettingsPage.saveConfig()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                                    <polyline points="17 21 17 13 7 13 7 21"/>
                                    <polyline points="7 3 7 8 15 8"/>
                                </svg>
                                Сохранить
                            </button>
                        </div>
                    </div>

                    <!-- Действия -->
                    <div class="card settings-actions-card">
                        <div class="settings-actions-row">
                            <div class="settings-action-item">
                                <div class="settings-action-info">
                                    <div class="settings-action-title">Сбросить к дефолтам</div>
                                    <div class="settings-action-desc">Восстановить все настройки по умолчанию</div>
                                </div>
                                <button class="btn btn-danger btn-sm" onclick="SettingsPage.resetConfig()">Сбросить</button>
                            </div>
                        </div>
                    </div>

                    <!-- Информация о системе -->
                    <div class="card settings-about-card">
                        <div class="settings-about-header">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" style="color: var(--accent);">
                                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                            </svg>
                            <div>
                                <div class="settings-about-title">Zapret Web-GUI</div>
                                <div class="settings-about-version">${GUI_VERSION}</div>
                            </div>
                        </div>
                        <div class="settings-about-info" id="settings-system-info">
                            <div class="settings-info-row">
                                <span class="settings-info-label">Загрузка информации о системе...</span>
                            </div>
                        </div>
                        <div class="settings-about-links">
                            <a href="https://github.com/avatarDD/zapret-gui" target="_blank" rel="noopener" class="settings-link">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                                </svg>
                                GitHub
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Скрытый input для импорта файла -->
            <input type="file" id="settings-import-file" accept=".json" style="display:none" onchange="SettingsPage.handleImportFile(this)">
        `;

        loadConfig();
        loadSystemInfo();
    }

    function renderSectionNav() {
        return SECTIONS.map(s => `
            <div class="settings-nav-item ${s.id === activeSection ? 'active' : ''}"
                 data-section="${s.id}" onclick="SettingsPage.switchSection('${s.id}')">
                <span class="settings-nav-icon">${s.icon}</span>
                <span class="settings-nav-label">${s.label}</span>
            </div>
        `).join('');
    }

    function renderSectionForm() {
        const section = SECTIONS.find(s => s.id === activeSection);
        if (!section) return;

        const formEl = document.getElementById('settings-form');
        if (!formEl) return;

        let html = `
            <div class="settings-section-header">
                <span class="settings-section-icon">${section.icon}</span>
                <h2 class="settings-section-title">${section.label}</h2>
            </div>
            <div class="settings-fields">
        `;

        section.fields.forEach(field => {
            // Проверяем условие видимости
            if (field.showIf) {
                const depValue = getNestedValue(config, field.showIf);
                if (!depValue) return;
            }

            const value = getNestedValue(config, field.key);
            html += renderField(field, value);
        });

        html += '</div>';
        formEl.innerHTML = html;
    }

    function renderField(field, value) {
        const id = 'cfg-' + field.key.replace(/\./g, '-');

        let inputHtml = '';

        switch (field.type) {
            case 'text':
            case 'password':
                inputHtml = `
                    <input type="${field.type}" class="form-input" id="${id}"
                           value="${escapeAttr(value || '')}"
                           placeholder="${field.placeholder || ''}"
                           onchange="SettingsPage.onFieldChange('${field.key}', this.value)">
                `;
                break;

            case 'number':
                inputHtml = `
                    <input type="number" class="form-input" id="${id}"
                           value="${value !== undefined && value !== null ? value : ''}"
                           placeholder="${field.placeholder || ''}"
                           ${field.min !== undefined ? 'min="' + field.min + '"' : ''}
                           ${field.max !== undefined ? 'max="' + field.max + '"' : ''}
                           onchange="SettingsPage.onFieldChange('${field.key}', this.valueAsNumber || parseInt(this.value))">
                `;
                break;

            case 'toggle':
                inputHtml = `
                    <label class="settings-toggle" for="${id}">
                        <input type="checkbox" id="${id}" ${value ? 'checked' : ''}
                               onchange="SettingsPage.onFieldChange('${field.key}', this.checked)">
                        <span class="settings-toggle-slider"></span>
                        <span class="settings-toggle-label">${value ? 'Вкл' : 'Выкл'}</span>
                    </label>
                `;
                break;

            case 'select':
                inputHtml = `
                    <select class="form-input form-select" id="${id}"
                            onchange="SettingsPage.onFieldChange('${field.key}', this.value)">
                        ${(field.options || []).map(o =>
                            `<option value="${o.value}" ${o.value === String(value) ? 'selected' : ''}>${o.label}</option>`
                        ).join('')}
                    </select>
                `;
                break;
        }

        return `
            <div class="settings-field">
                <label class="settings-field-label" for="${id}">${field.label}</label>
                <div class="settings-field-input">${inputHtml}</div>
            </div>
        `;
    }

    // ══════════════════ Data ══════════════════

    async function loadConfig() {
        loading = true;
        try {
            const data = await API.get('/api/config');
            if (data.ok && data.config) {
                config = data.config;
                originalConfig = JSON.parse(JSON.stringify(config));
                renderSectionForm();
            }
        } catch (err) {
            Toast.error('Ошибка загрузки конфигурации: ' + err.message);
        } finally {
            loading = false;
        }
    }

    async function loadSystemInfo() {
        try {
            const data = await API.get('/api/status');
            if (data.ok) {
                systemInfo = data;
                renderSystemInfo();
            }
        } catch (err) {
            // Не критично
        }
    }

    function renderSystemInfo() {
        const el = document.getElementById('settings-system-info');
        if (!el || !systemInfo) return;

        const sys = systemInfo.system || {};
        const nfqws = systemInfo.nfqws || {};
        const fw = systemInfo.firewall || {};
        const zapret = systemInfo.zapret || {};

        const rows = [];

        if (zapret.version) rows.push(['Версия zapret2', zapret.version]);
        if (sys.arch) rows.push(['Архитектура', sys.arch]);
        if (sys.kernel) rows.push(['Ядро', sys.kernel]);
        if (sys.platform) rows.push(['Платформа', sys.platform]);
        if (sys.uptime) rows.push(['Uptime системы', sys.uptime]);
        if (sys.ram_total) rows.push(['RAM', `${sys.ram_used || '?'} / ${sys.ram_total}`]);
        if (fw.type) rows.push(['Firewall', fw.type]);
        rows.push(['GUI версия', GUI_VERSION]);

        el.innerHTML = rows.map(([label, val]) => `
            <div class="settings-info-row">
                <span class="settings-info-label">${label}</span>
                <span class="settings-info-value">${val}</span>
            </div>
        `).join('');
    }

    // ══════════════════ Section Navigation ══════════════════

    function switchSection(sectionId) {
        activeSection = sectionId;

        // Обновить навигацию
        document.querySelectorAll('.settings-nav-item').forEach(el => {
            el.classList.toggle('active', el.dataset.section === sectionId);
        });

        renderSectionForm();
    }

    // ══════════════════ Field Changes ══════════════════

    function onFieldChange(key, value) {
        setNestedValue(config, key, value);
        hasUnsaved = !deepEqual(config, originalConfig);

        // Обновить toggle label
        const parts = key.split('.');
        const field = SECTIONS.flatMap(s => s.fields).find(f => f.key === key);
        if (field && field.type === 'toggle') {
            const id = 'cfg-' + key.replace(/\./g, '-');
            const labelEl = document.querySelector(`#${id} ~ .settings-toggle-label`);
            if (labelEl) labelEl.textContent = value ? 'Вкл' : 'Выкл';

            // Перерисовать форму если есть зависимые поля
            const hasDependents = SECTIONS.flatMap(s => s.fields).some(f => f.showIf === key);
            if (hasDependents) {
                renderSectionForm();
            }
        }

        updateSaveBar();
    }

    function updateSaveBar() {
        const bar = document.getElementById('settings-save-bar');
        if (bar) {
            bar.classList.toggle('hidden', !hasUnsaved);
        }
    }

    // ══════════════════ Save / Discard ══════════════════

    async function saveConfig() {
        try {
            // Собираем только изменённые секции
            const changes = {};
            for (const section of SECTIONS) {
                const sectionKey = section.id;
                if (!deepEqual(config[sectionKey], originalConfig[sectionKey])) {
                    changes[sectionKey] = config[sectionKey];
                }
            }

            if (Object.keys(changes).length === 0) {
                Toast.info('Нет изменений для сохранения');
                return;
            }

            const result = await API.put('/api/config', changes);
            if (result.ok) {
                originalConfig = JSON.parse(JSON.stringify(config));
                hasUnsaved = false;
                updateSaveBar();
                Toast.success('Настройки сохранены');

                // Предупреждение если изменились параметры сервера
                if (changes.gui && (changes.gui.host !== undefined || changes.gui.port !== undefined)) {
                    Toast.warning('Изменения порта/хоста вступят в силу после перезапуска GUI');
                }
            } else {
                Toast.error(result.error || 'Ошибка сохранения');
            }
        } catch (err) {
            Toast.error('Ошибка: ' + err.message);
        }
    }

    function discardChanges() {
        config = JSON.parse(JSON.stringify(originalConfig));
        hasUnsaved = false;
        updateSaveBar();
        renderSectionForm();
        Toast.info('Изменения отменены');
    }

    // ══════════════════ Reset ══════════════════

    async function resetConfig() {
        if (!confirm('Вы уверены, что хотите сбросить ВСЕ настройки к значениям по умолчанию?\n\nЭто действие нельзя отменить.')) return;

        try {
            const result = await API.post('/api/config/reset');
            if (result.ok) {
                config = result.config || {};
                originalConfig = JSON.parse(JSON.stringify(config));
                hasUnsaved = false;
                updateSaveBar();
                renderSectionForm();
                Toast.success('Настройки сброшены к дефолтам');
            } else {
                Toast.error(result.error || 'Ошибка сброса');
            }
        } catch (err) {
            Toast.error('Ошибка: ' + err.message);
        }
    }

    // ══════════════════ Import / Export ══════════════════

    async function exportConfig() {
        try {
            const result = await API.post('/api/config/export');
            if (result.ok && result.json) {
                const jsonStr = typeof result.json === 'string' ? result.json : JSON.stringify(JSON.parse(result.json), null, 2);
                const blob = new Blob([jsonStr], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'zapret-gui-config-' + new Date().toISOString().slice(0, 10) + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                Toast.success('Конфигурация экспортирована');
            }
        } catch (err) {
            Toast.error('Ошибка экспорта: ' + err.message);
        }
    }

    function importConfig() {
        const fileInput = document.getElementById('settings-import-file');
        if (fileInput) fileInput.click();
    }

    async function handleImportFile(input) {
        const file = input.files[0];
        if (!file) return;

        try {
            const text = await file.text();
            const json = JSON.parse(text);

            if (!confirm('Импортировать конфигурацию из файла?\n\nТекущие настройки будут заменены.')) {
                input.value = '';
                return;
            }

            const result = await API.post('/api/config/import', { json: json });
            if (result.ok) {
                await loadConfig();
                hasUnsaved = false;
                updateSaveBar();
                Toast.success('Конфигурация импортирована');
            } else {
                Toast.error(result.error || 'Ошибка импорта');
            }
        } catch (err) {
            Toast.error('Ошибка чтения файла: ' + err.message);
        } finally {
            input.value = '';
        }
    }

    // ══════════════════ Utils ══════════════════

    function getNestedValue(obj, path) {
        return path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : undefined, obj);
    }

    function setNestedValue(obj, path, value) {
        const keys = path.split('.');
        let current = obj;
        for (let i = 0; i < keys.length - 1; i++) {
            if (!current[keys[i]] || typeof current[keys[i]] !== 'object') {
                current[keys[i]] = {};
            }
            current = current[keys[i]];
        }
        current[keys[keys.length - 1]] = value;
    }

    function deepEqual(a, b) {
        if (a === b) return true;
        if (!a || !b) return false;
        if (typeof a !== typeof b) return false;
        if (typeof a !== 'object') return a === b;
        const keysA = Object.keys(a);
        const keysB = Object.keys(b);
        if (keysA.length !== keysB.length) return false;
        return keysA.every(k => deepEqual(a[k], b[k]));
    }

    function escapeAttr(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    // ══════════════════ Destroy ══════════════════

    function destroy() {
        hasUnsaved = false;
        loading = false;
        config = {};
        originalConfig = {};
        systemInfo = null;
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        switchSection,
        onFieldChange,
        saveConfig,
        discardChanges,
        resetConfig,
        exportConfig,
        importConfig,
        handleImportFile,
    };
})();


