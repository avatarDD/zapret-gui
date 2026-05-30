/**
 * singbox_configs.js — CRUD JSON-конфигов sing-box.
 *
 * Три вкладки:
 *   - Список        — карточки конфигов, кнопки запустить/остановить/удалить
 *   - Редактор      — JSON-textarea, save / validate / delete
 *   - Подписка      — импорт VLESS/Trojan/SS/Hy2/TUIC URI или URL подписки
 */

const SingboxConfigsPage = (() => {

    let activeTab = 'list';
    let configs = [];
    let env = null;
    let editName = '';
    let editText = '';
    let editDirty = false;
    let validateResult = null;

    // Импорт подписки
    let importUrl = '';
    let importText = '';
    let importResult = null;

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">sing-box — конфиги</h1>
                    <p class="page-description">
                        Управление JSON-конфигами и импорт VLESS / Trojan / SS / Hysteria2 / TUIC.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox'">
                        ← Инстансы
                    </button>
                </div>
            </div>

            <div class="tabs-bar" style="margin-bottom:12px;">
                <button class="tab-btn ${activeTab==='list' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('list')">Список</button>
                <button class="tab-btn ${activeTab==='builder' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('builder')">Конструктор</button>
                <button class="tab-btn ${activeTab==='editor' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('editor')">Редактор</button>
                <button class="tab-btn ${activeTab==='import' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('import')">Импорт</button>
                <button class="tab-btn ${activeTab==='subs' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('subs')">Подписки</button>
                <button class="tab-btn ${activeTab==='pool' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('pool')">Пул серверов</button>
            </div>

            <div id="sb-cfg-tab"></div>
        `;
        loadAll();
        readEditFromUrl();
    }

    function destroy() {
        if (testTimer) { clearTimeout(testTimer); testTimer = null; }
    }

    function switchTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.tabs-bar .tab-btn').forEach(b => b.classList.remove('active'));
        const map = { list:0, builder:1, editor:2, import:3, subs:4, pool:5 };
        const btns = document.querySelectorAll('.tabs-bar .tab-btn');
        if (btns[map[tab]]) btns[map[tab]].classList.add('active');
        if (tab === 'subs')    loadSubs();
        if (tab === 'builder') loadBuilder();
        if (tab === 'pool')    loadPool();
        renderTab();
    }

    // ══════════════ data ══════════════

    async function loadAll() {
        try {
            const [envResp, cfgsResp] = await Promise.all([
                API.get('/api/singbox/environment').catch(() => null),
                API.get('/api/singbox/configs').catch(() => null),
            ]);
            env     = envResp || null;
            configs = (cfgsResp && cfgsResp.configs) || [];
        } catch (e) {
            Toast.error(e.message);
        }
        renderTab();
    }

    function readEditFromUrl() {
        // #singbox-configs?edit=<name>
        const h = window.location.hash;
        const i = h.indexOf('?');
        if (i < 0) return;
        const qs = new URLSearchParams(h.slice(i + 1));
        const name = qs.get('edit');
        if (name) {
            openEditor(name);
        }
    }

    // ══════════════ tab: list ══════════════

    function renderTab() {
        const box = document.getElementById('sb-cfg-tab');
        if (!box) return;
        if (activeTab === 'list')    return renderListTab(box);
        if (activeTab === 'builder') return renderBuilderTab(box);
        if (activeTab === 'editor')  return renderEditorTab(box);
        if (activeTab === 'import')  return renderImportTab(box);
        if (activeTab === 'subs')    return renderSubsTab(box);
        if (activeTab === 'pool')    return renderPoolTab(box);
    }

    function renderListTab(box) {
        const newBtn = `
            <button class="btn btn-primary btn-sm"
                    onclick="SingboxConfigsPage.newConfig()">
                + Новый конфиг
            </button>`;

        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div class="text-muted">Конфигов нет.</div>
                        ${newBtn}
                    </div>
                </div>`;
            return;
        }

        const rows = configs.map(c => `
            <div class="card" style="margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:14px; font-weight:600;">
                            ${escapeHtml(c.name)}
                            ${c.running
                                ? '<span style="color:#39c45e; font-size:11px; margin-left:6px;">● running</span>'
                                : '<span class="text-muted" style="font-size:11px; margin-left:6px;">● stopped</span>'}
                        </div>
                        <div class="text-muted" style="font-size:11px;">
                            ${escapeHtml(c.path)} · ${Math.round(c.size / 1024)} KB
                        </div>
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-ghost btn-sm"
                                onclick="SingboxConfigsPage.openEditor('${escapeAttr(c.name)}')">
                            Редактировать
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="SingboxConfigsPage.validate('${escapeAttr(c.name)}')">
                            Проверить
                        </button>
                        ${c.running
                            ? `<button class="btn btn-ghost btn-sm"
                                       onclick="SingboxConfigsPage.toggle('${escapeAttr(c.name)}', false)">
                                   Остановить
                               </button>`
                            : `<button class="btn btn-primary btn-sm"
                                       onclick="SingboxConfigsPage.toggle('${escapeAttr(c.name)}', true)">
                                   Запустить
                               </button>`}
                        <button class="btn btn-ghost btn-sm"
                                onclick="SingboxConfigsPage.removeConfig('${escapeAttr(c.name)}')">
                            Удалить
                        </button>
                    </div>
                </div>
            </div>`).join('');

        box.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                <div class="text-muted" style="font-size:12px;">${configs.length} конфигов</div>
                ${newBtn}
            </div>
            ${rows}`;
    }

    // ══════════════ tab: editor ══════════════

    async function openEditor(name) {
        try {
            const r = await API.get(`/api/singbox/configs/${encodeURIComponent(name)}`);
            if (!r || !r.ok) {
                Toast.error((r && r.error) || 'Не удалось открыть');
                return;
            }
            editName = name;
            editText = r.text || '';
            editDirty = false;
            validateResult = null;
            activeTab = 'editor';
            // Обновим табы визуально
            const btns = document.querySelectorAll('.tabs-bar .tab-btn');
            btns.forEach(b => b.classList.remove('active'));
            if (btns[1]) btns[1].classList.add('active');
            renderTab();
        } catch (e) {
            Toast.error(e.message);
        }
    }

    function newConfig() {
        // Минимальный шаблон.
        editName = '';
        editText = JSON.stringify({
            "log": { "level": "info" },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 1080
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block",  "tag": "block"  }
            ],
            "route": { "final": "direct" }
        }, null, 2);
        editDirty = true;
        validateResult = null;
        activeTab = 'editor';
        const btns = document.querySelectorAll('.tabs-bar .tab-btn');
        btns.forEach(b => b.classList.remove('active'));
        if (btns[1]) btns[1].classList.add('active');
        renderTab();
    }

    function renderEditorTab(box) {
        const isNew = !editName;
        const validateBlock = validateResult ? renderValidateBlock(validateResult) : '';

        box.innerHTML = `
            <div class="card">
                <div style="display:flex; gap:8px; margin-bottom:8px;">
                    <input type="text" id="sb-editor-name"
                           class="form-input"
                           placeholder="Имя конфига (A-Za-z0-9._-)"
                           value="${escapeAttr(editName)}"
                           ${editName ? 'readonly' : ''}
                           style="flex:1;">
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.save()">
                        Сохранить
                    </button>
                    ${editName ? `
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxConfigsPage.validate(SingboxConfigsPage.currentName())">
                        sing-box check
                    </button>
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxConfigsPage.wrapIn('urltest')"
                            title="Обернуть все outbound'ы в urltest — sing-box будет автоматически выбирать самый быстрый">
                        Обернуть в urltest
                    </button>
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxConfigsPage.wrapIn('selector')"
                            title="Обернуть все outbound'ы в selector — переключение вручную через clash-api">
                        Обернуть в selector
                    </button>` : ''}
                </div>
                <textarea id="sb-editor-text"
                          class="form-textarea"
                          spellcheck="false"
                          style="width:100%; min-height:480px; font-family:monospace; font-size:12px;"
                          oninput="SingboxConfigsPage.onTextChange()"
                >${escapeHtml(editText)}</textarea>
                ${validateBlock}
            </div>`;
    }

    function renderValidateBlock(r) {
        if (r.ok) {
            return `<div class="alert alert-success" style="margin-top:10px;">
                <div class="alert-title">sing-box check: OK</div>
                ${r.stdout ? `<pre style="font-size:11px; margin:6px 0 0;">${escapeHtml(r.stdout)}</pre>` : ''}
            </div>`;
        }
        return `<div class="alert alert-warning" style="margin-top:10px;">
            <div class="alert-title">sing-box check: ошибки</div>
            <pre style="font-size:11px; margin:6px 0 0;">${escapeHtml(r.stderr || r.stdout || r.error || '?')}</pre>
        </div>`;
    }

    function onTextChange() {
        const ta = document.getElementById('sb-editor-text');
        if (ta) {
            editText = ta.value;
            editDirty = true;
        }
    }

    function currentName() {
        const nameEl = document.getElementById('sb-editor-name');
        return nameEl ? nameEl.value.trim() : editName;
    }

    async function save() {
        const name = currentName();
        if (!name) { Toast.error('Имя обязательно'); return; }
        const ta = document.getElementById('sb-editor-text');
        if (ta) editText = ta.value;
        try {
            const isExisting = configs.some(c => c.name === name);
            const url = isExisting
                ? `/api/singbox/configs/${encodeURIComponent(name)}`
                : `/api/singbox/configs`;
            const method = isExisting ? 'put' : 'post';
            const body = isExisting ? { text: editText }
                                    : { name, text: editText };
            const r = await API[method](url, body);
            if (r && r.ok) {
                Toast.success(`${name}: сохранён`);
                if (r.warnings && r.warnings.length) {
                    Toast.warn('Warnings: ' + r.warnings.join('; '));
                }
                editName = name;
                editDirty = false;
                await loadAll();
            } else {
                Toast.error((r && r.error) || 'save failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
    }

    async function wrapIn(groupType) {
        const name = currentName();
        if (!name) { Toast.error('Нет имени конфига'); return; }
        const tag = prompt(
            `Имя группы (tag нового ${groupType}-outbound'а):`,
            groupType === 'urltest' ? 'auto' : 'selector');
        if (!tag) return;
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(name)}/wrap`,
                { group_type: groupType, group_tag: tag });
            if (r && r.ok) {
                Toast.success(`${name}: обёрнут в ${groupType} '${tag}'`);
                await openEditor(name);   // перезагрузить редактор
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
    }

    async function validate(name) {
        try {
            const r = await API.post(
                `/api/singbox/configs/${encodeURIComponent(name)}/validate`);
            validateResult = r || { ok: false, error: 'no result' };
            renderTab();
        } catch (e) {
            validateResult = { ok: false, error: e.message };
            renderTab();
        }
    }

    async function toggle(name, on) {
        try {
            const op = on ? 'up' : 'down';
            const r = await API.post(`/api/singbox/configs/${encodeURIComponent(name)}/${op}`);
            if (r && r.ok) {
                Toast.success(`${name}: ${op} OK`);
            } else {
                Toast.error(`${name}: ${(r && r.error) || 'failed'}`);
                if (r && r.log_tail) console.warn(r.log_tail);
            }
        } catch (e) {
            Toast.error(e.message);
        }
        await loadAll();
    }

    async function removeConfig(name) {
        if (!confirm(`Удалить конфиг "${name}"?`)) return;
        try {
            const r = await API.delete(`/api/singbox/configs/${encodeURIComponent(name)}`);
            if (r && r.ok) {
                Toast.success(`${name}: удалён`);
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
        await loadAll();
    }

    // ══════════════ tab: import ══════════════

    function renderImportTab(box) {
        const resultBlock = importResult ? renderImportResult(importResult) : '';

        box.innerHTML = `
            <div class="card">
                <h3 style="margin-top:0;">Импорт подписки</h3>
                <p class="text-muted" style="font-size:12px;">
                    Подписка — URL или текст с одним или несколькими URI.
                    Поддерживаются <code>vless://</code>, <code>trojan://</code>,
                    <code>ss://</code>, <code>hysteria2://</code> / <code>hy2://</code>,
                    <code>tuic://</code>. Все они аггрегируются в один конфиг
                    <strong>imported-subscription</strong> в виде outbound'ов.
                    Тексты с base64-кодировкой декодируются автоматически.
                </p>

                <label class="form-label">URL подписки (опционально):</label>
                <input type="text" id="sb-imp-url"
                       class="form-input"
                       placeholder="https://example.com/subscribe?token=..."
                       value="${escapeAttr(importUrl)}"
                       oninput="SingboxConfigsPage.onImportUrlChange()">

                <label class="form-label" style="margin-top:10px;">или текст:</label>
                <textarea id="sb-imp-text"
                          class="form-textarea"
                          placeholder="vless://uuid@host:443?...#name\\nss://...\\n..."
                          style="width:100%; min-height:120px; font-family:monospace; font-size:12px;"
                          oninput="SingboxConfigsPage.onImportTextChange()">${escapeHtml(importText)}</textarea>

                <div style="margin-top:10px; display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxConfigsPage.importPreview()">
                        Предпросмотр
                    </button>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.importApply()">
                        Импортировать
                    </button>
                </div>

                ${resultBlock}
            </div>`;
    }

    function renderImportResult(r) {
        if (!r) return '';
        if (!r.ok) {
            return `<div class="alert alert-warning" style="margin-top:10px;">
                <div class="alert-title">Ошибка</div>
                <pre style="font-size:11px; margin:6px 0 0;">${escapeHtml(r.error || '?')}</pre>
            </div>`;
        }
        const s = r.summary || {};
        const rows = (r.items || []).map(it => {
            const status = it.ok
                ? `<span style="color:#39c45e;">OK</span>`
                : `<span style="color:#e58;">ERR</span>`;
            const meta = it.outbound_type
                ? `→ ${escapeHtml(it.outbound_type)} <strong>${escapeHtml(it.tag || '')}</strong>`
                : '';
            return `<tr>
                <td>${status}</td>
                <td>${escapeHtml(it.type || '?')}</td>
                <td>${meta}</td>
                <td class="text-muted" style="font-size:11px;">
                  ${escapeHtml(it.error || it.name || '')}
                </td>
            </tr>`;
        }).join('');

        return `<div class="alert alert-success" style="margin-top:10px;">
            <div class="alert-title">
                Импортировано: ${s.imported || 0} ·
                ошибок: ${s.errors || 0} ·
                пропущено: ${s.skipped || 0}
            </div>
            <table style="width:100%; font-size:12px; margin-top:8px;">
                <thead><tr>
                    <th style="text-align:left;">Status</th>
                    <th style="text-align:left;">Type</th>
                    <th style="text-align:left;">Result</th>
                    <th style="text-align:left;">Info</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
    }

    function onImportUrlChange() {
        const el = document.getElementById('sb-imp-url');
        if (el) importUrl = el.value.trim();
    }
    function onImportTextChange() {
        const el = document.getElementById('sb-imp-text');
        if (el) importText = el.value;
    }

    async function importPreview() {
        await doImport(false);
    }
    async function importApply() {
        await doImport(true);
    }

    async function doImport(save) {
        if (!importUrl && !importText) {
            Toast.error('Введите URL или текст подписки');
            return;
        }
        const url = save
            ? '/api/awg/subscription/import'
            : '/api/awg/subscription/preview';
        try {
            const r = await API.post(url, { url: importUrl, text: importText });
            importResult = r;
            renderTab();
            if (save) {
                if (r && r.ok) {
                    Toast.success(`Импорт: ${(r.summary || {}).imported || 0} записей`);
                }
                await loadAll();
            }
        } catch (e) {
            importResult = { ok: false, error: e.message };
            renderTab();
        }
    }

    // ══════════════ tab: builder (визуальный CRUD outbound'ов) ══════════════

    let builderTarget    = '';     // имя выбранного конфига
    let builderOutbounds = [];
    let builderForm      = null;   // null = не редактируем, иначе объект формы
    let builderBusy      = false;
    let builderAddNewName = '';    // имя нового конфига если создаём

    async function loadBuilder() {
        if (!builderTarget && configs.length) {
            // По умолчанию выбираем первый, который НЕ
            // imported-subscription-* (это автогенерёные подписочные).
            const own = configs.find(c => !c.name.startsWith('imported-subscription-'));
            builderTarget = (own || configs[0]).name;
        }
        if (builderTarget) {
            await loadBuilderOutbounds();
        } else {
            builderOutbounds = [];
            renderTab();
        }
    }

    async function loadBuilderOutbounds() {
        try {
            const r = await API.get(
                `/api/singbox/configs/${encodeURIComponent(builderTarget)}/outbounds`);
            builderOutbounds = (r && r.outbounds) || [];
        } catch (e) {
            builderOutbounds = [];
            Toast.error(e.message);
        }
        renderTab();
    }

    function renderBuilderTab(box) {
        // Список конфигов в выпадушке + кнопка «Новый конфиг».
        const cfgOpts = configs.map(c =>
            `<option value="${escapeAttr(c.name)}" ${c.name === builderTarget ? 'selected':''}>
                ${escapeHtml(c.name)}${c.name.startsWith('imported-subscription-') ? ' (подписка)' : ''}
            </option>`
        ).join('');

        if (!configs.length) {
            box.innerHTML = `
                <div class="card">
                    <h3 style="margin-top:0;">Конструктор outbound'ов</h3>
                    <p class="text-muted">
                        Сначала создайте конфиг — это можно сделать на вкладке
                        «Список» или «Редактор».
                    </p>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderQuickCreate()">
                        Создать пустой конфиг
                    </button>
                </div>`;
            return;
        }

        const formBlock = builderForm
            ? renderBuilderForm(builderForm)
            : '';

        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <label class="form-label" style="margin:0;">Конфиг:</label>
                    <select class="form-input" style="flex:0 0 auto; width:auto;"
                            onchange="SingboxConfigsPage.builderSwitchTarget(this.value)">
                        ${cfgOpts}
                    </select>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderAdd('vless')">+ VLESS</button>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderAdd('trojan')">+ Trojan</button>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderAdd('shadowsocks')">+ Shadowsocks</button>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderAdd('hysteria2')">+ Hysteria2</button>
                    <button class="btn btn-primary btn-sm"
                            onclick="SingboxConfigsPage.builderAdd('tuic')">+ TUIC</button>
                </div>
            </div>

            ${formBlock}

            ${renderBuilderOutboundsList()}
        `;
    }

    function renderBuilderOutboundsList() {
        if (!builderOutbounds.length) {
            return `<div class="card"><div class="text-muted">
                В конфиге нет outbound'ов. Используйте кнопки выше, чтобы добавить.
            </div></div>`;
        }
        const rows = builderOutbounds.map((o, idx) => {
            const t   = o.type || '?';
            const tag = o.tag || '(без tag)';
            const isService = t === 'direct' || t === 'block' || t === 'dns';
            const isGroup   = t === 'selector' || t === 'urltest';

            // Краткое описание
            let desc = '';
            if (isGroup) {
                desc = `tag'и: ${(o.outbounds || []).join(', ')}`;
            } else if (!isService) {
                const where = o.server && o.server_port
                    ? `${o.server}:${o.server_port}` : '';
                desc = where;
            } else {
                desc = '<span class="text-muted">служебный</span>';
            }

            const isEditable = !isService && !isGroup;
            return `
                <div class="card" style="margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
                        <div style="min-width:0; flex:1;">
                            <span style="font-weight:600;">${escapeHtml(tag)}</span>
                            <span class="text-muted" style="font-size:11px; margin-left:6px;">
                                ${escapeHtml(t)}
                            </span>
                            <div class="text-muted" style="font-size:12px;">${desc}</div>
                        </div>
                        <div style="display:flex; gap:6px;">
                            ${isEditable ? `
                            <button class="btn btn-ghost btn-sm"
                                    onclick="SingboxConfigsPage.builderEdit(${idx})">
                                Редактировать
                            </button>` : ''}
                            ${!isService ? `
                            <button class="btn btn-ghost btn-sm"
                                    onclick="SingboxConfigsPage.builderDelete('${escapeAttr(tag)}')">
                                Удалить
                            </button>` : ''}
                        </div>
                    </div>
                </div>`;
        }).join('');
        return rows;
    }

    function renderBuilderForm(form) {
        const editing = !!form._editing_tag;
        const isVless = form._form === 'vless';
        const isTrojan = form._form === 'trojan';
        const isSS = form._form === 'shadowsocks';
        const isHy2 = form._form === 'hysteria2';
        const isTuic = form._form === 'tuic';

        // Общие поля
        const commonFields = `
            <div style="display:grid; grid-template-columns:1fr 2fr 1fr; gap:8px;">
                <div>
                    <label class="form-label">Tag</label>
                    <input type="text" class="form-input"
                           value="${escapeAttr(form.tag || '')}"
                           ${editing ? 'readonly' : ''}
                           oninput="SingboxConfigsPage.builderFormSet('tag', this.value)">
                </div>
                <div>
                    <label class="form-label">Server</label>
                    <input type="text" class="form-input"
                           value="${escapeAttr(form.server || '')}"
                           oninput="SingboxConfigsPage.builderFormSet('server', this.value)">
                </div>
                <div>
                    <label class="form-label">Port</label>
                    <input type="number" class="form-input"
                           value="${form.port || ''}"
                           oninput="SingboxConfigsPage.builderFormSet('port', this.value)">
                </div>
            </div>`;

        // Auth-поля
        let authFields = '';
        if (isVless || isTuic) {
            authFields += `
                <label class="form-label" style="margin-top:6px;">UUID</label>
                <input type="text" class="form-input"
                       value="${escapeAttr(form.uuid || '')}"
                       oninput="SingboxConfigsPage.builderFormSet('uuid', this.value)">`;
        }
        if (isTrojan || isSS || isHy2 || isTuic) {
            const label = isTuic ? 'Password (опц.)' : 'Password';
            authFields += `
                <label class="form-label" style="margin-top:6px;">${label}</label>
                <input type="text" class="form-input"
                       value="${escapeAttr(form.password || '')}"
                       oninput="SingboxConfigsPage.builderFormSet('password', this.value)">`;
        }
        if (isSS) {
            authFields += `
                <label class="form-label" style="margin-top:6px;">Method (cipher)</label>
                <select class="form-input"
                        onchange="SingboxConfigsPage.builderFormSet('method', this.value)">
                    ${['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305',
                       '2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm',
                       'none']
                       .map(m => `<option value="${m}" ${m===(form.method||'aes-128-gcm') ? 'selected':''}>${m}</option>`).join('')}
                </select>`;
        }
        if (isVless) {
            authFields += `
                <label class="form-label" style="margin-top:6px;">Flow (опц., обычно xtls-rprx-vision для Reality)</label>
                <input type="text" class="form-input"
                       placeholder="xtls-rprx-vision"
                       value="${escapeAttr(form.flow || '')}"
                       oninput="SingboxConfigsPage.builderFormSet('flow', this.value)">`;
        }

        // Transport (для vless / trojan)
        let transportFields = '';
        if (isVless || isTrojan) {
            const tr = form.transport || 'tcp';
            transportFields = `
                <label class="form-label" style="margin-top:10px;">Transport</label>
                <select class="form-input"
                        onchange="SingboxConfigsPage.builderFormSet('transport', this.value)">
                    ${['tcp','ws','grpc'].map(t => `<option value="${t}" ${t===tr?'selected':''}>${t}</option>`).join('')}
                </select>`;
            if (tr === 'ws') {
                transportFields += `
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                        <div>
                            <label class="form-label">WS path</label>
                            <input type="text" class="form-input"
                                   placeholder="/"
                                   value="${escapeAttr(form.ws_path || '')}"
                                   oninput="SingboxConfigsPage.builderFormSet('ws_path', this.value)">
                        </div>
                        <div>
                            <label class="form-label">WS Host header (опц.)</label>
                            <input type="text" class="form-input"
                                   value="${escapeAttr(form.ws_host || '')}"
                                   oninput="SingboxConfigsPage.builderFormSet('ws_host', this.value)">
                        </div>
                    </div>`;
            } else if (tr === 'grpc') {
                transportFields += `
                    <label class="form-label">gRPC service name</label>
                    <input type="text" class="form-input"
                           value="${escapeAttr(form.grpc_service || '')}"
                           oninput="SingboxConfigsPage.builderFormSet('grpc_service', this.value)">`;
            }
        }

        // TLS / Reality (для vless / trojan / hy2 / tuic)
        let tlsFields = '';
        if (isVless || isTrojan) {
            const sec = form.security || (isTrojan ? 'tls' : '');
            tlsFields = `
                <label class="form-label" style="margin-top:10px;">Security</label>
                <select class="form-input"
                        onchange="SingboxConfigsPage.builderFormSet('security', this.value)">
                    ${['','tls','reality'].map(s => `<option value="${s}" ${s===sec?'selected':''}>${s || '(нет)'}</option>`).join('')}
                </select>`;
            if (sec === 'tls' || sec === 'reality') {
                tlsFields += `
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                        <div>
                            <label class="form-label">SNI / server_name</label>
                            <input type="text" class="form-input"
                                   value="${escapeAttr(form.sni || '')}"
                                   oninput="SingboxConfigsPage.builderFormSet('sni', this.value)">
                        </div>
                        <div>
                            <label class="form-label">uTLS fingerprint</label>
                            <select class="form-input"
                                    onchange="SingboxConfigsPage.builderFormSet('fingerprint', this.value)">
                                ${['','chrome','firefox','safari','ios','android','edge','random']
                                    .map(f => `<option value="${f}" ${f===(form.fingerprint||'')?'selected':''}>${f || '(не задано)'}</option>`).join('')}
                            </select>
                        </div>
                    </div>`;
            }
            if (sec === 'reality') {
                tlsFields += `
                    <div style="display:grid; grid-template-columns:2fr 1fr; gap:8px;">
                        <div>
                            <label class="form-label">Reality public key</label>
                            <input type="text" class="form-input"
                                   value="${escapeAttr(form.reality_pbk || '')}"
                                   oninput="SingboxConfigsPage.builderFormSet('reality_pbk', this.value)">
                        </div>
                        <div>
                            <label class="form-label">Short ID</label>
                            <input type="text" class="form-input"
                                   value="${escapeAttr(form.reality_sid || '')}"
                                   oninput="SingboxConfigsPage.builderFormSet('reality_sid', this.value)">
                        </div>
                    </div>`;
            }
        } else if (isHy2 || isTuic) {
            tlsFields = `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                    <div>
                        <label class="form-label">SNI</label>
                        <input type="text" class="form-input"
                               value="${escapeAttr(form.sni || '')}"
                               oninput="SingboxConfigsPage.builderFormSet('sni', this.value)">
                    </div>
                    <div style="display:flex; align-items:flex-end;">
                        <label style="display:flex; gap:6px; align-items:center;">
                            <input type="checkbox"
                                   ${form.insecure ? 'checked' : ''}
                                   onchange="SingboxConfigsPage.builderFormSet('insecure', this.checked)">
                            insecure (пропустить проверку TLS)
                        </label>
                    </div>
                </div>`;
        }

        return `
            <div class="card" style="margin-bottom:12px; border:1px solid var(--accent);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0;">
                        ${editing ? 'Редактирование' : 'Новый outbound'}:
                        <span class="text-muted">${form._form}</span>
                    </h3>
                    <button class="btn btn-ghost btn-sm"
                            onclick="SingboxConfigsPage.builderCancel()">
                        Отмена
                    </button>
                </div>
                ${commonFields}
                ${authFields}
                ${transportFields}
                ${tlsFields}
                <div style="margin-top:12px; display:flex; gap:8px;">
                    <button class="btn btn-primary btn-sm" ${builderBusy?'disabled':''}
                            onclick="SingboxConfigsPage.builderSave()">
                        Сохранить
                    </button>
                </div>
            </div>`;
    }

    function builderSwitchTarget(name) {
        builderTarget = name;
        builderForm = null;
        loadBuilderOutbounds();
    }

    function builderAdd(type) {
        builderForm = {
            _form: type,
            tag: type + '-' + Math.random().toString(36).slice(2, 6),
            server: '', port: 443,
            transport: 'tcp',
            security: (type === 'vless' || type === 'trojan') ? 'tls' : '',
        };
        renderTab();
    }

    function builderEdit(idx) {
        const ob = builderOutbounds[idx];
        if (!ob) return;
        // Восстанавливаем «плоскую» форму из готового outbound'а.
        const form = {
            _form: ob.type, _editing_tag: ob.tag,
            tag: ob.tag, server: ob.server || '',
            port: ob.server_port || 443,
        };
        if (ob.type === 'vless' || ob.type === 'tuic') form.uuid = ob.uuid || '';
        if (ob.type === 'trojan' || ob.type === 'shadowsocks'
                || ob.type === 'hysteria2' || ob.type === 'tuic') {
            form.password = ob.password || '';
        }
        if (ob.type === 'shadowsocks') form.method = ob.method || 'aes-128-gcm';
        if (ob.type === 'vless') form.flow = ob.flow || '';

        // Transport
        const tr = ob.transport;
        if (tr && tr.type) {
            form.transport = tr.type;
            if (tr.type === 'ws') {
                form.ws_path = tr.path || '';
                form.ws_host = (tr.headers && tr.headers.Host) || '';
            } else if (tr.type === 'grpc') {
                form.grpc_service = tr.service_name || '';
            }
        } else {
            form.transport = 'tcp';
        }

        // TLS
        const tls = ob.tls;
        if (tls && tls.enabled) {
            form.security = tls.reality && tls.reality.enabled ? 'reality' : 'tls';
            form.sni = tls.server_name || '';
            form.fingerprint = (tls.utls && tls.utls.fingerprint) || '';
            if (tls.reality) {
                form.reality_pbk = tls.reality.public_key || '';
                form.reality_sid = tls.reality.short_id || '';
            }
            if (tls.insecure) form.insecure = true;
        } else {
            form.security = '';
        }

        builderForm = form;
        renderTab();
    }

    function builderCancel() {
        builderForm = null;
        renderTab();
    }

    function builderFormSet(field, value) {
        if (!builderForm) return;
        if (field === 'port') {
            const n = parseInt(value, 10);
            builderForm.port = isNaN(n) ? 0 : n;
        } else {
            builderForm[field] = value;
        }
        // Не делаем перерисовку на каждый input — только на смену transport/security
        if (field === 'transport' || field === 'security') {
            renderTab();
        }
    }

    async function builderSave() {
        if (!builderForm || !builderTarget) return;
        builderBusy = true; renderTab();
        try {
            const editing = !!builderForm._editing_tag;
            const url = editing
                ? `/api/singbox/configs/${encodeURIComponent(builderTarget)}/outbounds/${encodeURIComponent(builderForm._editing_tag)}`
                : `/api/singbox/configs/${encodeURIComponent(builderTarget)}/outbounds`;
            const method = editing ? 'put' : 'post';
            const r = await API[method](url, builderForm);
            if (r && r.ok) {
                Toast.success(`Outbound сохранён (${r.outbounds_count} всего)`);
                builderForm = null;
                await loadBuilderOutbounds();
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        } finally {
            builderBusy = false; renderTab();
        }
    }

    async function builderDelete(tag) {
        if (!confirm(`Удалить outbound "${tag}"?`)) return;
        try {
            const r = await API.delete(
                `/api/singbox/configs/${encodeURIComponent(builderTarget)}/outbounds/${encodeURIComponent(tag)}`);
            if (r && r.ok) {
                Toast.success(`Удалён: ${tag}`);
                await loadBuilderOutbounds();
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
    }

    async function builderQuickCreate() {
        const name = prompt('Имя нового конфига:', 'my-vpn');
        if (!name) return;
        const text = JSON.stringify({
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ]
        });
        try {
            const r = await API.post('/api/singbox/configs', { name, text });
            if (r && r.ok) {
                Toast.success('Конфиг создан');
                builderTarget = name;
                await loadAll();
                await loadBuilderOutbounds();
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
    }

    // ══════════════ tab: subs (saved subscriptions + autorefresh) ══════════════

    let subs = [];
    let subForm = { name: '', url: '', format: 'auto', interval_hours: 6,
                    group: 'urltest' };
    let subBusy = false;

    async function loadSubs() {
        try {
            const r = await API.get('/api/singbox/subscriptions');
            subs = (r && r.subscriptions) || [];
        } catch (e) {
            Toast.error(e.message);
        }
        renderTab();
    }

    function renderSubsTab(box) {
        const formatOptions = ['auto', 'uri', 'clash', 'singbox-json']
            .map(f => `<option value="${f}" ${f===subForm.format?'selected':''}>${f}</option>`)
            .join('');

        const rows = subs.length ? subs.map(s => {
            const lastRel = s.last_refresh
                ? new Date(s.last_refresh * 1000).toLocaleString()
                : 'никогда';
            const statusBadge = s.last_status === 'ok'
                ? '<span style="color:#39c45e;">OK</span>'
                : (s.last_status === 'error'
                   ? `<span style="color:#e58;">ERR</span>`
                   : '<span class="text-muted">—</span>');
            return `
                <div class="card" style="margin-bottom:10px;">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
                        <div style="min-width:0; flex:1;">
                            <div style="font-size:14px; font-weight:600;">${escapeHtml(s.name)}
                                ${statusBadge}
                            </div>
                            <div class="text-muted" style="font-size:11px; word-break:break-all;">
                                ${escapeHtml(s.url)}
                            </div>
                            <div class="text-muted" style="font-size:11px;">
                                format: ${escapeHtml(s.format || 'auto')} ·
                                группа: ${escapeHtml(s.group || 'urltest')} ·
                                каждые ${s.interval_hours || 6}ч ·
                                outbound'ов: ${s.last_outbounds || 0} ·
                                обновлено: ${lastRel}
                                ${s.last_error ? ' · <span style="color:#e58;">' + escapeHtml(s.last_error) + '</span>' : ''}
                            </div>
                        </div>
                        <div style="display:flex; gap:6px;">
                            <button class="btn btn-primary btn-sm" ${subBusy?'disabled':''}
                                    onclick="SingboxConfigsPage.subsRefresh('${escapeAttr(s.id)}')">
                                Обновить
                            </button>
                            <button class="btn btn-ghost btn-sm"
                                    onclick="SingboxConfigsPage.subsRemove('${escapeAttr(s.id)}')">
                                Удалить
                            </button>
                        </div>
                    </div>
                </div>`;
        }).join('') : '<div class="text-muted">Сохранённых подписок нет.</div>';

        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Новая подписка с автообновлением</h3>
                <p class="text-muted" style="font-size:12px;">
                    Подписка скачивается раз в N часов; outbound'ы сохраняются
                    в конфиг <code>imported-subscription-&lt;id&gt;</code>.
                    Поддерживаются форматы: <strong>uri</strong> (base64/plain
                    text-URI), <strong>clash</strong> (YAML с секцией proxies),
                    <strong>singbox-json</strong> (готовый sing-box config).
                    <strong>auto</strong> — определит сам по содержимому.
                </p>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
                    <div>
                        <label class="form-label">Имя:</label>
                        <input type="text" class="form-input"
                               value="${escapeAttr(subForm.name)}"
                               oninput="SingboxConfigsPage.subFormSet('name', this.value)">
                    </div>
                    <div>
                        <label class="form-label">Интервал (часы):</label>
                        <input type="number" class="form-input" min="1" step="1"
                               value="${subForm.interval_hours}"
                               oninput="SingboxConfigsPage.subFormSet('interval_hours', this.value)">
                    </div>
                </div>
                <label class="form-label" style="margin-top:6px;">URL:</label>
                <input type="text" class="form-input"
                       placeholder="https://provider.example/subscribe?token=..."
                       value="${escapeAttr(subForm.url)}"
                       oninput="SingboxConfigsPage.subFormSet('url', this.value)">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-top:6px;">
                    <div>
                        <label class="form-label">Формат:</label>
                        <select class="form-input"
                                onchange="SingboxConfigsPage.subFormSet('format', this.value)">
                            ${formatOptions}
                        </select>
                    </div>
                    <div>
                        <label class="form-label">Переключение серверов:</label>
                        <select class="form-input"
                                onchange="SingboxConfigsPage.subFormSet('group', this.value)">
                            <option value="urltest" ${subForm.group==='urltest'?'selected':''}>urltest — авто (быстрейший живой)</option>
                            <option value="selector" ${subForm.group==='selector'?'selected':''}>selector — вручную</option>
                            <option value="none" ${subForm.group==='none'?'selected':''}>none — только первый сервер</option>
                        </select>
                    </div>
                </div>
                <p class="text-muted" style="font-size:11px; margin:6px 0 0;">
                    <strong>urltest</strong> (рекомендуется): sing-box сам
                    пингует серверы и бесшовно переключается на живой с
                    минимальной задержкой — если сервер «упал», трафик
                    мгновенно идёт через другой, без перезапуска.
                </p>
                <div style="margin-top:10px;">
                    <button class="btn btn-primary btn-sm" ${subBusy?'disabled':''}
                            onclick="SingboxConfigsPage.subsAdd()">
                        Добавить и обновить
                    </button>
                    <button class="btn btn-ghost btn-sm" ${subBusy?'disabled':''}
                            onclick="SingboxConfigsPage.subsRefreshAll()">
                        Обновить все
                    </button>
                </div>
            </div>

            <h3 style="margin:0 0 6px;">Сохранённые подписки</h3>
            ${rows}`;
    }

    function subFormSet(field, value) {
        if (field === 'interval_hours') {
            const n = parseInt(value, 10);
            subForm.interval_hours = (isNaN(n) || n < 1) ? 6 : n;
        } else {
            subForm[field] = value;
        }
    }

    async function subsAdd() {
        if (!subForm.name || !subForm.url) {
            Toast.error('Нужны имя и URL'); return;
        }
        subBusy = true; renderTab();
        try {
            const add = await API.post('/api/singbox/subscriptions', subForm);
            if (!add || !add.ok) {
                Toast.error((add && add.error) || 'add failed');
                return;
            }
            Toast.success('Подписка добавлена, начинаем загрузку...');
            // Сразу force-refresh
            const refresh = await API.post(
                `/api/singbox/subscriptions/${encodeURIComponent(add.id)}/refresh`);
            if (refresh && refresh.ok) {
                Toast.success(`Загружено ${refresh.outbounds || 0} outbound'ов`);
                subForm = { name:'', url:'', format:'auto', interval_hours:6,
                            group:'urltest' };
            } else {
                Toast.error((refresh && refresh.error) || 'refresh failed');
            }
            await loadSubs();
            await loadAll();
        } catch (e) {
            Toast.error(e.message);
        } finally {
            subBusy = false; renderTab();
        }
    }

    async function subsRefresh(sid) {
        subBusy = true; renderTab();
        try {
            const r = await API.post(`/api/singbox/subscriptions/${encodeURIComponent(sid)}/refresh`);
            if (r && r.ok) {
                Toast.success(`Обновлено: ${r.outbounds || 0} outbound'ов (${r.format})`);
            } else {
                Toast.error((r && r.error) || 'refresh failed');
            }
            await loadSubs();
            await loadAll();
        } catch (e) {
            Toast.error(e.message);
        } finally {
            subBusy = false; renderTab();
        }
    }

    async function subsRefreshAll() {
        subBusy = true; renderTab();
        try {
            await API.post('/api/singbox/subscriptions/refresh-all');
            Toast.success('Обновление всех подписок запущено');
            await loadSubs();
            await loadAll();
        } catch (e) {
            Toast.error(e.message);
        } finally {
            subBusy = false; renderTab();
        }
    }

    async function subsRemove(sid) {
        if (!confirm('Удалить подписку и связанный конфиг?')) return;
        try {
            await API.delete(`/api/singbox/subscriptions/${encodeURIComponent(sid)}`);
            Toast.success('Удалено');
            await loadSubs();
            await loadAll();
        } catch (e) {
            Toast.error(e.message);
        }
    }

    // ══════════════ tab: pool (публичные источники + тестер) ══════════════

    let pool = { settings: {}, sources: [], presets: [], refresher: {} };
    let poolBusy = false;
    let poolSrcForm = { name: '', url: '', format: 'auto' };
    let testState = { running: false, result: null,
                      progress: { phase: '', done: 0, total: 0 } };
    let testTimer = null;

    async function loadPool() {
        try {
            const r = await API.get('/api/singbox/pool');
            if (r && r.ok) {
                pool = { settings: r.settings || {}, sources: r.sources || [],
                         presets: r.presets || [], refresher: r.refresher || {} };
            }
        } catch (e) { Toast.error(e.message); }
        renderTab();
    }

    function renderPoolTab(box) {
        const s = pool.settings || {};
        const lastRel = s.last_refresh
            ? new Date(s.last_refresh * 1000).toLocaleString() : 'никогда';
        const statusBadge = s.last_status === 'ok'
            ? '<span style="color:#39c45e;">OK</span>'
            : (s.last_status === 'error'
               ? `<span style="color:#e58;">ERR</span>` : '<span class="text-muted">—</span>');

        const presetBtns = (pool.presets || []).map(p => `
            <button class="btn btn-ghost btn-sm" ${p.added||poolBusy?'disabled':''}
                    title="${escapeAttr(p.url)}"
                    onclick="SingboxConfigsPage.poolAddPreset('${escapeAttr(p.url)}')">
                ${p.added ? '✓ ' : '+ '}${escapeHtml(p.name)}
            </button>`).join(' ');

        const srcRows = (pool.sources || []).length
            ? pool.sources.map(src => `
                <div class="card" style="margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
                        <div style="min-width:0; flex:1;">
                            <label style="display:flex; align-items:center; gap:6px; font-size:13px; font-weight:600;">
                                <input type="checkbox" ${src.enabled?'checked':''}
                                       onchange="SingboxConfigsPage.poolToggleSrc('${escapeAttr(src.id)}', this.checked)">
                                ${escapeHtml(src.name)}
                            </label>
                            <div class="text-muted" style="font-size:11px; word-break:break-all;">
                                ${escapeHtml(src.url)} · format: ${escapeHtml(src.format||'auto')}
                            </div>
                        </div>
                        <button class="btn btn-ghost btn-sm"
                                onclick="SingboxConfigsPage.poolRemoveSrc('${escapeAttr(src.id)}')">Удалить</button>
                    </div>
                </div>`).join('')
            : '<div class="text-muted">Источников нет. Добавьте из рекомендованных или свой URL.</div>';

        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Что это</h3>
                <p class="text-muted" style="font-size:12px;">
                    Пул собирает серверы из <strong>публичных источников</strong>
                    (свалки бесплатных ключей), дедуплицирует их и складывает в
                    один конфиг <code>${escapeHtml(s.config_name||'server-pool')}</code>,
                    обёрнутый в группу <strong>urltest</strong> — sing-box сам
                    выбирает живой быстрейший сервер и бесшовно переключается.
                    Если источник вернул пусто — берётся прошлый успешный набор
                    (текущие серверы не теряются).
                    Качество бесплатных ключей низкое, поэтому включите
                    <strong>фильтр живых</strong> — мусор отсеется тестом.
                </p>
            </div>

            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Рекомендованные источники</h3>
                <div style="display:flex; flex-wrap:wrap; gap:6px;">${presetBtns}</div>
            </div>

            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Свой источник</h3>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
                    <div>
                        <label class="form-label">Имя:</label>
                        <input type="text" class="form-input" value="${escapeAttr(poolSrcForm.name)}"
                               oninput="SingboxConfigsPage.poolSrcSet('name', this.value)">
                    </div>
                    <div>
                        <label class="form-label">Формат:</label>
                        <select class="form-input" onchange="SingboxConfigsPage.poolSrcSet('format', this.value)">
                            ${['auto','uri','clash','singbox-json'].map(f=>`<option value="${f}" ${f===poolSrcForm.format?'selected':''}>${f}</option>`).join('')}
                        </select>
                    </div>
                </div>
                <label class="form-label" style="margin-top:6px;">URL (raw .txt со ссылками vmess/vless/ss/… или base64):</label>
                <input type="text" class="form-input"
                       placeholder="https://raw.githubusercontent.com/.../configs.txt"
                       value="${escapeAttr(poolSrcForm.url)}"
                       oninput="SingboxConfigsPage.poolSrcSet('url', this.value)">
                <div style="margin-top:10px;">
                    <button class="btn btn-primary btn-sm" ${poolBusy?'disabled':''}
                            onclick="SingboxConfigsPage.poolAddSrc()">Добавить источник</button>
                </div>
            </div>

            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Источники</h3>
                ${srcRows}
            </div>

            <div class="card" style="margin-bottom:12px;">
                <h3 style="margin-top:0;">Настройки пула</h3>
                <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:8px;">
                    <div>
                        <label class="form-label">Интервал обновления (часы):</label>
                        <input type="number" class="form-input" min="1" value="${s.interval_hours||12}"
                               onchange="SingboxConfigsPage.poolSet('interval_hours', this.value)">
                    </div>
                    <div>
                        <label class="form-label">Макс. серверов (cap):</label>
                        <input type="number" class="form-input" min="1" value="${s.cap||100}"
                               onchange="SingboxConfigsPage.poolSet('cap', this.value)">
                    </div>
                    <div>
                        <label class="form-label">Группа:</label>
                        <select class="form-input" onchange="SingboxConfigsPage.poolSet('group', this.value)">
                            <option value="urltest" ${s.group==='urltest'?'selected':''}>urltest — авто</option>
                            <option value="selector" ${s.group==='selector'?'selected':''}>selector — вручную</option>
                        </select>
                    </div>
                    <div>
                        <label class="form-label">Цель теста:</label>
                        <select class="form-input" onchange="SingboxConfigsPage.poolSet('target', this.value)">
                            ${['cloudflare','amazon','google'].map(t=>`<option value="${t}" ${s.target===t?'selected':''}>${t}</option>`).join('')}
                        </select>
                    </div>
                </div>
                <label style="display:flex; align-items:center; gap:6px; margin-top:8px; font-size:13px;">
                    <input type="checkbox" ${s.health_filter?'checked':''}
                           onchange="SingboxConfigsPage.poolSet('health_filter', this.checked)">
                    Фильтр живых при сборке (тест через движок, оставить только рабочие)
                </label>
            </div>

            <div class="card" style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                    <div class="text-muted" style="font-size:12px;">
                        Статус: ${statusBadge} ·
                        серверов: ${s.last_count||0} ·
                        обновлён: ${lastRel}
                        ${s.last_error ? ' · <span style="color:#e58;">'+escapeHtml(s.last_error)+'</span>' : ''}
                    </div>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-primary btn-sm" ${poolBusy?'disabled':''}
                                onclick="SingboxConfigsPage.poolRefresh()">Собрать пул сейчас</button>
                        <button class="btn btn-ghost btn-sm" ${testState.running?'disabled':''}
                                onclick="SingboxConfigsPage.testConfig('${escapeAttr(s.config_name||'server-pool')}')">
                            ${testState.running?'Тест идёт…':'Тест серверов'}
                        </button>
                    </div>
                </div>
            </div>

            ${renderTestResults()}`;
    }

    function renderTestResults() {
        const res = testState.result;
        if (testState.running) {
            const p = testState.progress || { phase: '', done: 0, total: 0 };
            const phaseLabel = p.phase === 'e2e'
                ? 'Проверка через движок до облака'
                : 'TCP-отсев живых';
            const total = p.total || 0;
            const done = p.done || 0;
            const pct = total > 0 ? Math.round((done / total) * 100) : 0;
            return `
                <div class="card">
                    <div style="display:flex; justify-content:space-between; font-size:12px;">
                        <span class="text-muted">${phaseLabel}…</span>
                        <span class="text-muted">${done} / ${total}${total?` (${pct}%)`:''}</span>
                    </div>
                    <div style="height:6px; background:var(--bg-input); border-radius:4px; overflow:hidden; margin-top:6px;">
                        <div style="height:100%; width:${pct}%; background:var(--accent); transition:width .3s;"></div>
                    </div>
                </div>`;
        }
        if (!res) return '';
        if (!res.ok) {
            return `<div class="card"><span style="color:#e58;">${escapeHtml(res.error||'ошибка теста')}</span></div>`;
        }
        const sum = res.summary || {};
        const engineNote = res.engine_used
            ? `проверка через движок до <code>${escapeHtml(res.target||'')}</code>`
            : `только TCP (sing-box не установлен — e2e-замер пропущен)`;
        const rows = (res.results||[]).map(r => {
            const dot = r.alive ? '#39c45e' : '#e58';
            const lat = r.latency_ms != null ? `${r.latency_ms} ms` : '—';
            const stage = r.stage === 'e2e' ? 'e2e' : 'tcp';
            return `<tr>
                <td><span style="color:${dot};">●</span> ${escapeHtml(r.tag)}</td>
                <td class="text-muted" style="font-size:11px;">${escapeHtml(r.type||'')}</td>
                <td class="text-muted" style="font-size:11px;">${escapeHtml(String(r.server||''))}:${escapeHtml(String(r.port||''))}</td>
                <td>${r.alive?'<span style="color:#39c45e;">жив</span>':'<span style="color:#e58;">мёртв</span>'}</td>
                <td>${lat}</td>
                <td class="text-muted" style="font-size:11px;">${stage}${r.error?(' · '+escapeHtml(r.error)):''}</td>
            </tr>`;
        }).join('');
        return `
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <h3 style="margin:0;">Результат теста</h3>
                    <div class="text-muted" style="font-size:12px;">
                        живых ${sum.alive||0} / ${sum.total||0} · ${engineNote}
                    </div>
                </div>
                <div style="overflow-x:auto;">
                    <table style="width:100%; border-collapse:collapse; font-size:12px;">
                        <thead><tr style="text-align:left;">
                            <th>Сервер</th><th>Тип</th><th>Endpoint</th>
                            <th>Статус</th><th>Задержка</th><th>Стадия</th>
                        </tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </div>`;
    }

    function poolSrcSet(field, value) { poolSrcForm[field] = value; }

    async function poolAddSrc() {
        if (!poolSrcForm.name || !poolSrcForm.url) {
            Toast.error('Нужны имя и URL'); return;
        }
        poolBusy = true; renderTab();
        try {
            const r = await API.post('/api/singbox/pool/sources', poolSrcForm);
            if (r && r.ok) {
                Toast.success('Источник добавлен');
                poolSrcForm = { name:'', url:'', format:'auto' };
                await loadPool();
            } else { Toast.error((r&&r.error)||'не удалось'); }
        } catch (e) { Toast.error(e.message); }
        finally { poolBusy = false; renderTab(); }
    }

    async function poolAddPreset(url) {
        const p = (pool.presets||[]).find(x => x.url === url);
        poolBusy = true; renderTab();
        try {
            const r = await API.post('/api/singbox/pool/sources',
                { name: (p&&p.name)||url, url, format: (p&&p.format)||'auto' });
            if (r && r.ok) { Toast.success('Добавлен'); await loadPool(); }
            else { Toast.error((r&&r.error)||'не удалось'); }
        } catch (e) { Toast.error(e.message); }
        finally { poolBusy = false; renderTab(); }
    }

    async function poolToggleSrc(sid, enabled) {
        try {
            await API.put(`/api/singbox/pool/sources/${encodeURIComponent(sid)}`, { enabled });
            await loadPool();
        } catch (e) { Toast.error(e.message); }
    }

    async function poolRemoveSrc(sid) {
        if (!confirm('Удалить источник?')) return;
        try {
            await API.delete(`/api/singbox/pool/sources/${encodeURIComponent(sid)}`);
            await loadPool();
        } catch (e) { Toast.error(e.message); }
    }

    async function poolSet(field, value) {
        const body = {};
        if (field === 'health_filter') body[field] = !!value;
        else if (field === 'interval_hours' || field === 'cap') body[field] = parseInt(value, 10);
        else body[field] = value;
        try {
            await API.post('/api/singbox/pool/settings', body);
            await loadPool();
        } catch (e) { Toast.error(e.message); }
    }

    async function poolRefresh() {
        poolBusy = true; renderTab();
        Toast.info('Собираем пул… (может занять время при включённом фильтре живых)');
        try {
            const r = await API.post('/api/singbox/pool/refresh');
            if (r && r.ok) {
                Toast.success(`Пул собран: ${r.count} серверов (из ${r.total_before_filter||r.count})`);
            } else { Toast.error((r&&r.error)||'не удалось собрать'); }
            await loadPool();
        } catch (e) { Toast.error(e.message); }
        finally { poolBusy = false; renderTab(); }
    }

    // ── tester (общий: можно вызвать на любой конфиг) ──

    async function testConfig(configName) {
        try {
            const r = await API.post('/api/singbox/test', { config: configName });
            if (!r || !r.ok) {
                Toast.error((r&&r.error) || 'не удалось запустить тест');
                return;
            }
            Toast.info(`Тестируем ${r.count} серверов…`);
            testState.running = true; testState.result = null;
            testState.progress = { phase: 'tcp', done: 0, total: r.count || 0 };
            renderTab();
            pollTest();
        } catch (e) { Toast.error(e.message); }
    }

    function pollTest() {
        if (testTimer) clearTimeout(testTimer);
        testTimer = setTimeout(async () => {
            try {
                const st = await API.get('/api/singbox/test/status');
                testState.running = !!st.running;
                if (st.progress) testState.progress = st.progress;
                if (!st.running && st.result && Object.keys(st.result).length) {
                    testState.result = st.result;
                    renderTab();
                    return;
                }
                renderTab();
                if (st.running) pollTest();
            } catch (e) {
                testState.running = false; renderTab();
            }
        }, 1000);
    }

    // ══════════════ helpers ══════════════

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escapeAttr(s) {
        return escapeHtml(s).replace(/"/g, '&quot;');
    }

    return {
        render, destroy, switchTab,
        openEditor, newConfig, removeConfig,
        save, validate, toggle, wrapIn,
        onTextChange, currentName,
        importPreview, importApply,
        onImportUrlChange, onImportTextChange,
        // Subscriptions
        subFormSet, subsAdd, subsRefresh, subsRefreshAll, subsRemove,
        // Server pool + tester
        poolSrcSet, poolAddSrc, poolAddPreset, poolToggleSrc, poolRemoveSrc,
        poolSet, poolRefresh, testConfig,
        // Builder
        builderSwitchTarget, builderAdd, builderEdit, builderCancel,
        builderFormSet, builderSave, builderDelete, builderQuickCreate,
    };
})();
