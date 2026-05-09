/**
 * awg_configs.js — Управление конфигами AmneziaWG.
 *
 * Список конфигов слева, текстовый редактор справа.
 * Поддерживает create / edit / delete / import (paste/upload .conf) /
 * export (download), валидация перед сохранением.
 */

const AwgConfigsPage = (() => {

    let configs = [];
    let currentName = null;     // выбранный конфиг
    let editorText = "";
    let editorDirty = false;
    let creating = false;       // режим создания нового

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">AmneziaWG — конфиги</h1>
                    <p class="page-description">Создание, редактирование и импорт .conf-файлов.</p>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='awg'">
                        ← Туннели
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="AwgConfigsPage.startCreate()">
                        + Новый
                    </button>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 280px 1fr; gap: 12px;">
                <!-- Список -->
                <div class="card" style="padding: 0;">
                    <div class="card-title" style="padding: 12px 12px 8px 12px;">
                        Конфиги <span class="text-muted" id="awg-cfg-count" style="margin-left: 6px;"></span>
                    </div>
                    <div id="awg-cfg-list" style="max-height: 70vh; overflow-y: auto;"></div>
                </div>

                <!-- Редактор -->
                <div class="card">
                    <div class="card-title" style="justify-content: space-between;">
                        <span id="awg-cfg-editor-title">Выберите конфиг или создайте новый</span>
                        <div id="awg-cfg-editor-actions" style="display: none; gap: 6px;">
                            <input type="file" id="awg-cfg-file-input" accept=".conf,text/plain"
                                   style="display:none;" onchange="AwgConfigsPage.importFile(event)"/>
                            <button class="btn btn-ghost btn-sm"
                                    onclick="document.getElementById('awg-cfg-file-input').click()">
                                Импорт
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="AwgConfigsPage.exportCurrent()">
                                Экспорт
                            </button>
                            <button class="btn btn-ghost btn-sm" onclick="AwgConfigsPage.generateKeypair()">
                                Новые ключи
                            </button>
                            <button class="btn btn-ghost btn-sm text-danger"
                                    onclick="AwgConfigsPage.deleteCurrent()" id="awg-cfg-delete-btn">
                                Удалить
                            </button>
                        </div>
                    </div>

                    <div id="awg-cfg-name-row" style="display:none; margin-top: 8px;">
                        <label class="form-label">Имя конфига</label>
                        <input type="text" class="form-input" id="awg-cfg-name"
                               placeholder="например: awg0"
                               oninput="AwgConfigsPage.onNameInput()"/>
                        <div class="text-muted" style="font-size: 12px; margin-top: 4px;">
                            До 15 символов: латиница, цифры, '_', '-', '.'.
                        </div>
                    </div>

                    <textarea id="awg-cfg-editor"
                              style="width: 100%; min-height: 400px; margin-top: 10px;
                                     font-family: monospace; font-size: 13px;
                                     padding: 10px; border: 1px solid var(--border);
                                     border-radius: 4px; background: var(--bg-secondary);
                                     color: var(--text-primary); display: none;"
                              spellcheck="false"
                              oninput="AwgConfigsPage.onEditorInput()"
                              placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 10.0.0.2/32&#10;DNS = 1.1.1.1&#10;Jc = 4&#10;Jmin = 40&#10;Jmax = 70&#10;...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;AllowedIPs = 0.0.0.0/0&#10;Endpoint = host:port"></textarea>

                    <div id="awg-cfg-errors" style="margin-top: 8px;"></div>

                    <div id="awg-cfg-save-row" style="display:none; margin-top: 10px;
                                                       display: none; gap: 8px;">
                        <button class="btn btn-primary btn-sm" onclick="AwgConfigsPage.save()">
                            Сохранить
                        </button>
                        <button class="btn btn-ghost btn-sm" onclick="AwgConfigsPage.cancelEdit()">
                            Отмена
                        </button>
                        <span class="text-muted" id="awg-cfg-status" style="margin-left: 12px;"></span>
                    </div>
                </div>
            </div>
        `;

        loadConfigs().then(() => {
            // Поддержка #awg-configs?edit=<name>
            const m = (window.location.hash || '').match(/edit=([^&]+)/);
            if (m) {
                openConfig(decodeURIComponent(m[1]));
            }
        });
    }

    function destroy() {}

    // ══════════════ data ══════════════

    async function loadConfigs() {
        try {
            const data = await API.get('/api/awg/configs');
            configs = data.configs || [];
            renderList();
        } catch (err) {
            const list = document.getElementById('awg-cfg-list');
            if (list) list.innerHTML = `<div class="text-muted" style="padding: 12px;">Ошибка: ${escapeHtml(err.message)}</div>`;
        }
    }

    function renderList() {
        const list = document.getElementById('awg-cfg-list');
        const count = document.getElementById('awg-cfg-count');
        if (count) count.textContent = configs.length ? `(${configs.length})` : '';

        if (!list) return;
        if (configs.length === 0) {
            list.innerHTML = `<div class="text-muted" style="padding: 12px;">Конфигов пока нет</div>`;
            return;
        }
        list.innerHTML = configs.map(c => `
            <div class="list-item ${c.name === currentName ? 'active' : ''}"
                 style="padding: 10px 12px; cursor: pointer; border-bottom: 1px solid var(--border);
                        ${c.name === currentName ? 'background: var(--bg-active);' : ''}"
                 onclick="AwgConfigsPage.openConfig('${escapeAttr(c.name)}')">
                <div style="display:flex; justify-content: space-between; align-items: center;">
                    <strong style="font-family: monospace;">${escapeHtml(c.name)}</strong>
                    ${c.active
                        ? `<span class="status-dot running" title="активен"></span>`
                        : `<span class="status-dot stopped" title="остановлен"></span>`}
                </div>
                <div class="text-muted" style="font-size: 11px; margin-top: 2px;">
                    ${formatSize(c.size)}
                </div>
            </div>
        `).join('');
    }

    // ══════════════ open / create ══════════════

    async function openConfig(name) {
        if (editorDirty && !confirm('Несохранённые изменения будут потеряны. Продолжить?')) {
            return;
        }
        creating = false;
        currentName = name;
        try {
            const data = await API.get(`/api/awg/configs/${encodeURIComponent(name)}`);
            const cfg = data.config || {};
            editorText = cfg.text || '';
            editorDirty = false;
            renderList();
            renderEditor(cfg.errors || []);
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function startCreate() {
        if (editorDirty && !confirm('Несохранённые изменения будут потеряны. Продолжить?')) {
            return;
        }
        creating = true;
        currentName = '';
        editorText = `[Interface]
PrivateKey =
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1280

# AmneziaWG обфускация
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey =
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint =
PersistentKeepalive = 25
`;
        editorDirty = true;
        renderList();
        renderEditor([]);
    }

    function renderEditor(errors) {
        const titleEl = document.getElementById('awg-cfg-editor-title');
        const actions = document.getElementById('awg-cfg-editor-actions');
        const nameRow = document.getElementById('awg-cfg-name-row');
        const nameIn  = document.getElementById('awg-cfg-name');
        const editor  = document.getElementById('awg-cfg-editor');
        const saveRow = document.getElementById('awg-cfg-save-row');
        const errBox  = document.getElementById('awg-cfg-errors');
        const delBtn  = document.getElementById('awg-cfg-delete-btn');

        if (titleEl) {
            titleEl.textContent = creating
                ? 'Новый конфиг'
                : (currentName ? `Конфиг: ${currentName}` : 'Выберите конфиг или создайте новый');
        }
        if (actions) actions.style.display = (creating || currentName) ? 'flex' : 'none';
        if (delBtn) delBtn.style.display = creating ? 'none' : '';
        if (nameRow) nameRow.style.display = creating ? '' : 'none';
        if (nameIn && creating) nameIn.value = currentName || '';

        if (editor) {
            editor.style.display = (creating || currentName) ? 'block' : 'none';
            editor.value = editorText;
        }
        if (saveRow) saveRow.style.display = (creating || currentName) ? 'flex' : 'none';

        renderErrors(errors);
    }

    function renderErrors(errors) {
        const errBox = document.getElementById('awg-cfg-errors');
        if (!errBox) return;
        if (!errors || !errors.length) {
            errBox.innerHTML = '';
            return;
        }
        errBox.innerHTML = `
            <div style="padding: 8px 12px; background: var(--bg-warning, #5a1c1c);
                        border-left: 3px solid #c0392b; font-size: 12px;">
                <strong>Ошибки валидации:</strong>
                <ul style="margin: 4px 0 0 18px;">
                    ${errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // ══════════════ editor events ══════════════

    function onEditorInput() {
        const editor = document.getElementById('awg-cfg-editor');
        editorText = editor ? editor.value : '';
        editorDirty = true;
        // Лёгкая live-валидация (debounced)
        scheduleValidate();
    }

    function onNameInput() {
        const inp = document.getElementById('awg-cfg-name');
        currentName = inp ? inp.value.trim() : '';
        editorDirty = true;
    }

    let validateTimer = null;
    function scheduleValidate() {
        if (validateTimer) clearTimeout(validateTimer);
        validateTimer = setTimeout(async () => {
            try {
                const data = await API.post('/api/awg/configs/validate', { text: editorText });
                renderErrors(data.errors || []);
            } catch (_) {}
        }, 500);
    }

    function cancelEdit() {
        if (editorDirty && !confirm('Отменить изменения?')) return;
        editorDirty = false;
        if (creating) {
            creating = false;
            currentName = null;
            editorText = '';
            renderList();
            renderEditor([]);
        } else if (currentName) {
            openConfig(currentName);
        }
    }

    // ══════════════ save / delete ══════════════

    async function save() {
        if (!editorText.trim()) {
            Toast.error('Конфиг пуст');
            return;
        }
        const status = document.getElementById('awg-cfg-status');
        if (status) status.textContent = 'Сохранение...';

        try {
            let resp;
            if (creating) {
                if (!currentName) {
                    Toast.error('Введите имя конфига');
                    if (status) status.textContent = '';
                    return;
                }
                resp = await API.post('/api/awg/configs', {
                    name: currentName,
                    text: editorText,
                });
            } else {
                resp = await API.put(`/api/awg/configs/${encodeURIComponent(currentName)}`,
                                     { text: editorText });
            }
            const cfg = resp.config || {};
            editorDirty = false;
            creating = false;
            currentName = cfg.name || currentName;
            editorText = cfg.text || editorText;

            Toast.success('Сохранено');
            if (status) status.textContent = '';
            await loadConfigs();
            renderEditor(cfg.errors || []);
        } catch (err) {
            Toast.error(err.message);
            if (status) status.textContent = '';
        }
    }

    async function deleteCurrent() {
        if (!currentName || creating) return;
        if (!confirm(`Удалить конфиг "${currentName}"? Если он активен — туннель будет опущен.`)) return;
        try {
            await API.delete(`/api/awg/configs/${encodeURIComponent(currentName)}`);
            Toast.success('Удалено');
            currentName = null;
            editorText = '';
            editorDirty = false;
            await loadConfigs();
            renderEditor([]);
        } catch (err) {
            Toast.error(err.message);
        }
    }

    // ══════════════ import / export / keypair ══════════════

    function importFile(event) {
        const file = event.target.files && event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result || '';
            const editor = document.getElementById('awg-cfg-editor');
            if (editor) {
                editor.value = text;
                editorText = text;
                editorDirty = true;
                if (creating && !currentName) {
                    // подсказать имя из имени файла
                    const base = file.name.replace(/\.conf$/i, '');
                    const inp = document.getElementById('awg-cfg-name');
                    if (inp && !inp.value) {
                        inp.value = base.slice(0, 15);
                        currentName = inp.value;
                    }
                }
                scheduleValidate();
            }
        };
        reader.readAsText(file);
        event.target.value = '';
    }

    function exportCurrent() {
        if (!editorText) return;
        const name = currentName || 'awg';
        const blob = new Blob([editorText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}.conf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function generateKeypair() {
        try {
            const data = await API.post('/api/awg/keypair');
            if (data.ok) {
                const msg = `PrivateKey: ${data.private_key}\nPublicKey: ${data.public_key}\n\n` +
                            `Вставить PrivateKey в [Interface] текущего конфига?`;
                if (confirm(msg)) {
                    insertOrReplaceField('PrivateKey', data.private_key);
                }
            } else {
                Toast.error(data.error || 'Не удалось сгенерировать');
            }
        } catch (err) {
            Toast.error(err.message);
        }
    }

    function insertOrReplaceField(key, value) {
        const editor = document.getElementById('awg-cfg-editor');
        if (!editor) return;
        const lines = editorText.split('\n');
        let inInterface = false;
        let replaced = false;
        for (let i = 0; i < lines.length; i++) {
            const t = lines[i].trim();
            if (/^\[Interface\]$/i.test(t)) {
                inInterface = true;
                continue;
            }
            if (/^\[/.test(t)) {
                if (inInterface && !replaced) {
                    lines.splice(i, 0, `${key} = ${value}`);
                    replaced = true;
                }
                inInterface = false;
                continue;
            }
            if (inInterface && t.startsWith(key)) {
                lines[i] = `${key} = ${value}`;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            // конца файла — дописываем
            if (inInterface) lines.push(`${key} = ${value}`);
            else lines.unshift(`[Interface]\n${key} = ${value}`);
        }
        editorText = lines.join('\n');
        editor.value = editorText;
        editorDirty = true;
        scheduleValidate();
    }

    // ══════════════ helpers ══════════════

    function formatSize(n) {
        n = +n || 0;
        if (n < 1024) return `${n} B`;
        return `${(n / 1024).toFixed(1)} KB`;
    }

    function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    }
    function escapeAttr(s) {
        return String(s || '').replace(/'/g, '&#39;').replace(/"/g, '&quot;');
    }

    return {
        render, destroy,
        openConfig, startCreate, cancelEdit,
        save, deleteCurrent,
        onEditorInput, onNameInput,
        importFile, exportCurrent, generateKeypair,
    };
})();
