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
                <button class="tab-btn ${activeTab==='editor' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('editor')">Редактор</button>
                <button class="tab-btn ${activeTab==='import' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('import')">Импорт</button>
                <button class="tab-btn ${activeTab==='subs' ? 'active':''}"
                        onclick="SingboxConfigsPage.switchTab('subs')">Подписки</button>
            </div>

            <div id="sb-cfg-tab"></div>
        `;
        loadAll();
        readEditFromUrl();
    }

    function destroy() {
        // ничего пока не держим
    }

    function switchTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.tabs-bar .tab-btn').forEach(b => b.classList.remove('active'));
        const map = { list:0, editor:1, import:2, subs:3 };
        const btns = document.querySelectorAll('.tabs-bar .tab-btn');
        if (btns[map[tab]]) btns[map[tab]].classList.add('active');
        if (tab === 'subs') loadSubs();
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
        if (activeTab === 'list')   return renderListTab(box);
        if (activeTab === 'editor') return renderEditorTab(box);
        if (activeTab === 'import') return renderImportTab(box);
        if (activeTab === 'subs')   return renderSubsTab(box);
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

    // ══════════════ tab: subs (saved subscriptions + autorefresh) ══════════════

    let subs = [];
    let subForm = { name: '', url: '', format: 'auto', interval_hours: 6 };
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
                <label class="form-label" style="margin-top:6px;">Формат:</label>
                <select class="form-input"
                        onchange="SingboxConfigsPage.subFormSet('format', this.value)">
                    ${formatOptions}
                </select>
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
                subForm = { name:'', url:'', format:'auto', interval_hours:6 };
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
    };
})();
