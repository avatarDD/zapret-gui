/**
 * awg_warp.js — Импорт и нативная генерация AWG-WARP конфигов.
 *
 * Табы:
 *   - Импорт       (готовый .conf от стороннего генератора)
 *   - Генерация    (нативно через Cloudflare WARP API)
 *   - WARP-in-WARP (двойной туннель: outer → inner)
 */

const AwgWarpPage = (() => {

    let activeTab = 'import';
    let importText = '';
    let importing = false;

    // ── Generate tab state ─────────────────────────────────────────
    let generating  = false;
    let genResult   = null;     // последний результат /generate
    let genLicense  = '';
    let genName     = '';
    let savingGen   = false;

    // ── WARP-in-WARP tab state ─────────────────────────────────────
    let wiwLoading      = false;
    let wiwBusy         = false;     // setup/teardown в процессе
    let wiwStatus       = null;      // последний ответ /api/awg/warp-in-warp
    let wiwConfigs      = [];        // список существующих AWG-конфигов
    let wiwOuter        = '';        // выбранное имя outer
    let wiwInner        = '';        // выбранное имя inner
    let wiwRefreshTimer = null;

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">WARP</h1>
                    <p class="page-description">
                        Cloudflare WARP через AmneziaWG — импорт и генерация конфигов.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='awg'">
                        ← Туннели
                    </button>
                </div>
            </div>

            <div class="tabs-bar">
                <button class="tab-btn ${activeTab === 'import' ? 'active' : ''}"
                        onclick="AwgWarpPage.switchTab('import')">
                    Импорт
                </button>
                <button class="tab-btn ${activeTab === 'generate' ? 'active' : ''}"
                        onclick="AwgWarpPage.switchTab('generate')">
                    Генерация
                </button>
                <button class="tab-btn ${activeTab === 'wiw' ? 'active' : ''}"
                        onclick="AwgWarpPage.switchTab('wiw')">
                    WARP-in-WARP
                </button>
            </div>

            <div class="card" style="border-top-left-radius:0; border-top-right-radius:0;">
                <div id="awg-warp-tab-content"></div>
            </div>
        `;

        renderTab();
    }

    function destroy() {
        stopWiwRefresh();
    }

    // ══════════════ tabs ══════════════

    function switchTab(tab) {
        activeTab = tab;
        // Обновить header кнопок
        document.querySelectorAll('.tabs-bar .tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        const map = { import: 0, generate: 1, wiw: 2 };
        const idx = map[tab];
        const btns = document.querySelectorAll('.tabs-bar .tab-btn');
        if (btns[idx]) btns[idx].classList.add('active');

        // На WiW-табе включаем периодический рефреш статуса.
        if (tab === 'wiw') {
            loadWiwData();
            startWiwRefresh();
        } else {
            stopWiwRefresh();
        }

        renderTab();
    }

    function renderTab() {
        const box = document.getElementById('awg-warp-tab-content');
        if (!box) return;
        if (activeTab === 'import')   return renderImportTab(box);
        if (activeTab === 'generate') return renderGenerateTab(box);
        if (activeTab === 'wiw')      return renderWiwTab(box);
    }

    // ══════════════ tab: Импорт ══════════════

    function renderImportTab(box) {
        box.innerHTML = `
            <p class="text-muted" style="margin: 0 0 12px 0;">
                Вставьте содержимое .conf, сгенерированного на стороннем сервисе
                (например,
                <a href="https://warp-generator.github.io" target="_blank" rel="noopener">
                    warp-generator.github.io
                </a>),
                или загрузите файл. Конфиг будет сохранён как обычный AWG-туннель.
            </p>

            <div style="display:flex; gap:8px; align-items:center; margin-bottom:8px;">
                <label class="form-label" style="margin:0;">Имя (опционально)</label>
                <input type="text" class="form-input" id="awg-warp-name"
                       style="max-width: 220px;"
                       placeholder="warp-1 (по умолчанию)"
                       maxlength="15"/>
                <input type="file" id="awg-warp-file-input" accept=".conf,text/plain"
                       style="display:none;"
                       onchange="AwgWarpPage.onFile(event)"/>
                <button class="btn btn-ghost btn-sm"
                        onclick="document.getElementById('awg-warp-file-input').click()">
                    Загрузить файл
                </button>
            </div>

            <textarea id="awg-warp-text"
                      style="width:100%; min-height: 320px;
                             font-family: monospace; font-size: 13px;
                             padding: 10px; border: 1px solid var(--border);
                             border-radius: 4px; background: var(--bg-secondary);
                             color: var(--text-primary);"
                      spellcheck="false"
                      placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 172.16.0.2/32, 2606:4700:110:....&#10;DNS = 1.1.1.1&#10;Jc = 4&#10;...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;AllowedIPs = 0.0.0.0/0, ::/0&#10;Endpoint = 162.159.192.x:2408"
                      oninput="AwgWarpPage.onTextInput()">${escapeHtml(importText)}</textarea>

            <div id="awg-warp-import-status" style="margin-top: 8px;"></div>

            <div style="margin-top: 12px; display:flex; gap:8px; align-items:center;">
                <button class="btn btn-primary btn-sm"
                        id="awg-warp-import-btn"
                        onclick="AwgWarpPage.doImport()"
                        ${importing ? 'disabled' : ''}>
                    Импортировать
                </button>
                <button class="btn btn-ghost btn-sm" onclick="AwgWarpPage.clearText()">
                    Очистить
                </button>
            </div>
        `;
    }

    function renderGenerateTab(box) {
        const previewHtml = genResult ? renderGenPreview(genResult) : '';

        box.innerHTML = `
            <p class="text-muted" style="margin: 0 0 12px 0;">
                Сгенерировать новый AWG-WARP конфиг напрямую через
                Cloudflare WARP API — без сторонних сайтов. На вашем
                устройстве должен быть выход в интернет.
            </p>

            <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:flex-end; margin-bottom:8px;">
                <div style="display:flex; flex-direction:column; gap:4px; flex: 1 1 220px;">
                    <label class="form-label" style="margin:0;">
                        WARP+ ключ (опционально)
                    </label>
                    <input type="text" class="form-input" id="awg-warp-license"
                           placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX"
                           value="${escapeHtml(genLicense)}"
                           oninput="AwgWarpPage.onLicenseInput()"
                           ${generating ? 'disabled' : ''}/>
                </div>
                <div style="display:flex; flex-direction:column; gap:4px; flex: 0 0 220px;">
                    <label class="form-label" style="margin:0;">
                        Имя конфига (опционально)
                    </label>
                    <input type="text" class="form-input" id="awg-warp-gen-name"
                           placeholder="warp-gen-<auto>"
                           maxlength="15"
                           value="${escapeHtml(genName)}"
                           oninput="AwgWarpPage.onGenNameInput()"
                           ${generating ? 'disabled' : ''}/>
                </div>
                <div>
                    <button class="btn btn-primary"
                            id="awg-warp-gen-btn"
                            onclick="AwgWarpPage.doGenerate()"
                            ${generating ? 'disabled' : ''}>
                        ${generating ? 'Генерация...' : 'Сгенерировать'}
                    </button>
                </div>
            </div>

            <div id="awg-warp-gen-status" style="margin-top: 8px;"></div>

            <div id="awg-warp-gen-preview" style="margin-top: 12px;">
                ${previewHtml}
            </div>
        `;
    }

    function renderGenPreview(res) {
        const acc = res.account || {};
        const warningsHtml = (res.warnings && res.warnings.length)
            ? `<div style="margin-top:8px; padding: 8px 10px;
                          background: rgba(211, 158, 0, 0.12);
                          border-left: 3px solid #d39e00; font-size: 12px;">
                   <strong>Предупреждения:</strong>
                   <ul style="margin: 4px 0 0 18px;">
                      ${res.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
                   </ul>
               </div>`
            : '';

        const savedHtml = res.saved
            ? `<div style="padding: 8px 10px; background: rgba(46, 160, 67, 0.1);
                          border-left: 3px solid #2ea043; font-size: 13px;
                          margin-bottom: 10px;">
                   Конфиг сохранён как <strong>${escapeHtml(res.name)}</strong>.
               </div>`
            : `<div style="display:flex; gap:8px; align-items:center;
                          margin-bottom: 10px;">
                   <input type="text" class="form-input" id="awg-warp-gen-savename"
                          placeholder="${escapeHtml(res.name || 'warp-gen-...')}"
                          value="${escapeHtml(res.name || '')}"
                          maxlength="15"
                          style="max-width: 240px;"/>
                   <button class="btn btn-primary btn-sm"
                           id="awg-warp-gen-save-btn"
                           onclick="AwgWarpPage.doSaveGenerated()"
                           ${savingGen ? 'disabled' : ''}>
                       ${savingGen ? 'Сохранение...' : 'Сохранить конфиг'}
                   </button>
                   <button class="btn btn-ghost btn-sm" onclick="AwgWarpPage.discardGenerated()">
                       Отбросить
                   </button>
               </div>`;

        const accInfo = `
            <div style="display:grid; grid-template-columns: max-content 1fr;
                        gap: 4px 12px; font-size: 12px; margin-bottom: 8px;
                        color: var(--text-secondary);">
                <div>Тип:</div>
                <div>${escapeHtml(acc.type || '—')}${acc.warp_plus ? ' (WARP+)' : ''}</div>
                <div>Endpoint:</div>
                <div>${escapeHtml(acc.endpoint || '—')}</div>
                <div>IPv4:</div>
                <div>${escapeHtml(acc.client_v4 || '—')}</div>
                <div>IPv6:</div>
                <div>${escapeHtml(acc.client_v6 || '—')}</div>
            </div>
        `;

        return `
            ${savedHtml}
            ${accInfo}
            ${warningsHtml}
            <label class="form-label" style="margin: 8px 0 4px 0;">Содержимое .conf</label>
            <textarea readonly
                      style="width:100%; min-height: 280px;
                             font-family: monospace; font-size: 12px;
                             padding: 10px; border: 1px solid var(--border);
                             border-radius: 4px; background: var(--bg-secondary);
                             color: var(--text-primary);">${escapeHtml(res.text || '')}</textarea>
            ${res.saved ? `
                <div style="margin-top: 10px; display:flex; gap:8px;">
                    <button class="btn btn-primary btn-sm"
                            onclick="window.location.hash='awg-configs?edit=${encodeURIComponent(res.name)}'">
                        Открыть в редакторе
                    </button>
                    <button class="btn btn-ghost btn-sm"
                            onclick="window.location.hash='awg'">
                        К туннелям
                    </button>
                </div>
            ` : ''}
        `;
    }

    // ══════════════ tab: WARP-in-WARP ══════════════

    function renderWiwTab(box) {
        if (wiwLoading && !wiwStatus) {
            box.innerHTML = `
                <div class="text-muted" style="padding: 32px; text-align: center;">
                    Загрузка...
                </div>`;
            return;
        }

        const active = !!(wiwStatus && wiwStatus.active);

        const intro = `
            <p class="text-muted" style="margin: 0 0 12px 0;">
                Двойной туннель: пользовательский трафик идёт сначала
                через <strong>outer</strong> (первый WARP), а внутри
                него — через <strong>inner</strong> (второй WARP).
                Это меняет внешний IP дважды и помогает обойти ограничения,
                настроенные под одиночный WARP.
            </p>
            <p class="text-muted" style="margin: 0 0 16px 0; font-size: 12px;">
                Рекомендуется заранее сгенерировать или импортировать
                два разных WARP-конфига на вкладках «Импорт» / «Генерация».
            </p>
        `;

        if (active) {
            box.innerHTML = intro + renderWiwActiveBlock(wiwStatus);
        } else {
            box.innerHTML = intro + renderWiwSetupBlock();
        }
    }

    function renderWiwSetupBlock() {
        const opts = wiwConfigs
            .map(c => `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`)
            .join('');

        if (!wiwConfigs.length) {
            return `
                <div style="padding: 12px; background: rgba(211, 158, 0, 0.10);
                            border-left: 3px solid #d39e00; font-size: 13px;
                            margin-bottom: 12px;">
                    Нет ни одного WARP-конфига. Создайте хотя бы два — на
                    вкладках «Импорт» или «Генерация» — а потом возвращайтесь сюда.
                </div>`;
        }

        return `
            <div style="display:flex; flex-wrap:wrap; gap:12px; margin-bottom: 12px;">
                <div style="display:flex; flex-direction:column; gap:4px; min-width: 220px;">
                    <label class="form-label" style="margin:0;">
                        Outer (первый туннель, через WAN)
                    </label>
                    <select class="form-input" id="awg-wiw-outer"
                            ${wiwBusy ? 'disabled' : ''}
                            onchange="AwgWarpPage.onWiwOuterChange()">
                        <option value="">— выберите —</option>
                        ${opts}
                    </select>
                </div>
                <div style="display:flex; flex-direction:column; gap:4px; min-width: 220px;">
                    <label class="form-label" style="margin:0;">
                        Inner (второй туннель, через outer)
                    </label>
                    <select class="form-input" id="awg-wiw-inner"
                            ${wiwBusy ? 'disabled' : ''}
                            onchange="AwgWarpPage.onWiwInnerChange()">
                        <option value="">— выберите —</option>
                        ${opts}
                    </select>
                </div>
            </div>

            <div id="awg-wiw-status" style="margin-bottom: 8px;"></div>

            <div style="display:flex; gap:8px;">
                <button class="btn btn-primary"
                        id="awg-wiw-setup-btn"
                        onclick="AwgWarpPage.doWiwSetup()"
                        ${wiwBusy ? 'disabled' : ''}>
                    ${wiwBusy ? 'Запуск...' : 'Создать двойной туннель'}
                </button>
                <button class="btn btn-ghost btn-sm"
                        onclick="AwgWarpPage.refreshWiw()"
                        ${wiwBusy ? 'disabled' : ''}>
                    Обновить
                </button>
            </div>
        `;
    }

    function renderWiwActiveBlock(st) {
        const outer = (st.state && st.state.outer) || '—';
        const inner = (st.state && st.state.inner) || '—';
        const ipV4  = (st.state && st.state.inner_endpoint_ip) || '';
        const ipV6  = (st.state && st.state.inner_endpoint_v6) || '';

        const dot = (ok) => `<span style="display:inline-block; width:8px; height:8px;
            border-radius:50%; background: ${ok ? '#2ea043' : '#c0392b'};
            margin-right: 6px;"></span>`;

        const healthColor = st.healthy ? '#2ea043' : '#d39e00';
        const healthText  = st.healthy ? 'Активен' : 'Активен с предупреждениями';

        return `
            <div style="padding: 10px 12px; background: rgba(46, 160, 67, 0.10);
                        border-left: 3px solid ${healthColor};
                        font-size: 13px; margin-bottom: 12px;">
                <div style="font-weight: 600; color: ${healthColor};
                            margin-bottom: 4px;">
                    ${escapeHtml(healthText)}
                </div>
                <div style="display:grid; grid-template-columns: max-content 1fr;
                            gap: 4px 12px; font-size: 12px;">
                    <div>Outer:</div>
                    <div>${dot(st.outer_running)}<strong>${escapeHtml(outer)}</strong></div>
                    <div>Inner:</div>
                    <div>${dot(st.inner_running)}<strong>${escapeHtml(inner)}</strong></div>
                    ${ipV4 ? `
                    <div>Маршрут IPv4:</div>
                    <div>${dot(st.route_v4_ok)}${escapeHtml(ipV4)}/32 → ${escapeHtml(outer)}</div>` : ''}
                    ${ipV6 ? `
                    <div>Маршрут IPv6:</div>
                    <div>${dot(st.route_v6_ok)}${escapeHtml(ipV6)}/128 → ${escapeHtml(outer)}</div>` : ''}
                </div>
            </div>

            ${renderWiwPeerStats('Outer', st.outer_status)}
            ${renderWiwPeerStats('Inner', st.inner_status)}

            <div style="display:flex; gap:8px; margin-top: 12px;">
                <button class="btn btn-danger"
                        onclick="AwgWarpPage.doWiwTeardown()"
                        ${wiwBusy ? 'disabled' : ''}>
                    ${wiwBusy ? 'Отключение...' : 'Отключить'}
                </button>
                <button class="btn btn-ghost btn-sm"
                        onclick="AwgWarpPage.refreshWiw()"
                        ${wiwBusy ? 'disabled' : ''}>
                    Обновить
                </button>
            </div>
        `;
    }

    function renderWiwPeerStats(label, status) {
        const peers = (status && status.peers) || [];
        if (!peers.length) return '';
        const rows = peers.map(p => {
            const hs = p.latest_handshake
                ? formatHandshake(p.latest_handshake) : 'нет';
            const rx = formatBytes(p.rx_bytes || 0);
            const tx = formatBytes(p.tx_bytes || 0);
            return `
                <tr>
                    <td style="font-family: monospace; font-size: 11px;
                               max-width: 220px; overflow: hidden;
                               text-overflow: ellipsis; white-space: nowrap;">
                        ${escapeHtml((p.public_key || '').slice(0, 20))}…
                    </td>
                    <td>${escapeHtml(hs)}</td>
                    <td>↓ ${rx}</td>
                    <td>↑ ${tx}</td>
                </tr>`;
        }).join('');
        return `
            <div style="margin-top: 8px;">
                <div style="font-size: 12px; color: var(--text-secondary);
                            margin-bottom: 4px;">${escapeHtml(label)}</div>
                <table style="width:100%; font-size: 12px;
                              border-collapse: collapse;">
                    <thead>
                        <tr style="color: var(--text-muted);">
                            <th style="text-align:left;">Peer</th>
                            <th style="text-align:left;">Handshake</th>
                            <th style="text-align:left;">RX</th>
                            <th style="text-align:left;">TX</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    }

    async function loadWiwData() {
        wiwLoading = true;
        try {
            const [statusResp, configsResp] = await Promise.all([
                API.get('/api/awg/warp-in-warp'),
                API.get('/api/awg/configs'),
            ]);
            wiwStatus = statusResp || { ok: false, active: false };
            wiwConfigs = (configsResp && configsResp.configs) || [];

            // Если нет выбранных значений — взять из state, если активен
            if (wiwStatus.active && wiwStatus.state) {
                wiwOuter = wiwStatus.state.outer || wiwOuter;
                wiwInner = wiwStatus.state.inner || wiwInner;
            }
        } catch (err) {
            wiwStatus = { ok: false, active: false, error: err.message };
        } finally {
            wiwLoading = false;
            if (activeTab === 'wiw') {
                renderTab();
                // восстановить значения <select> после рендера
                const o = document.getElementById('awg-wiw-outer');
                const i = document.getElementById('awg-wiw-inner');
                if (o && wiwOuter) o.value = wiwOuter;
                if (i && wiwInner) i.value = wiwInner;
            }
        }
    }

    function startWiwRefresh() {
        stopWiwRefresh();
        wiwRefreshTimer = setInterval(() => {
            if (activeTab !== 'wiw' || wiwBusy) return;
            loadWiwData();
        }, 5000);
    }

    function stopWiwRefresh() {
        if (wiwRefreshTimer) {
            clearInterval(wiwRefreshTimer);
            wiwRefreshTimer = null;
        }
    }

    function refreshWiw() {
        loadWiwData();
    }

    function onWiwOuterChange() {
        const sel = document.getElementById('awg-wiw-outer');
        wiwOuter = sel ? sel.value : '';
    }

    function onWiwInnerChange() {
        const sel = document.getElementById('awg-wiw-inner');
        wiwInner = sel ? sel.value : '';
    }

    async function doWiwSetup() {
        if (wiwBusy) return;
        if (!wiwOuter || !wiwInner) {
            Toast.error('Выберите outer и inner');
            return;
        }
        if (wiwOuter === wiwInner) {
            Toast.error('Outer и inner должны различаться');
            return;
        }

        const status = document.getElementById('awg-wiw-status');
        if (status) {
            status.innerHTML = `<span class="text-muted">
                Поднимаем outer, пиним маршрут, поднимаем inner...
            </span>`;
        }

        wiwBusy = true;
        renderTab();

        try {
            const resp = await API.post('/api/awg/warp-in-warp', {
                outer: wiwOuter,
                inner: wiwInner,
            });
            if (!resp.ok) throw new Error(resp.error || 'Ошибка запуска');
            Toast.success('WARP-in-WARP активен');
            await loadWiwData();
        } catch (err) {
            Toast.error(err.message || 'Ошибка');
            if (status) {
                status.innerHTML = `
                    <div style="padding: 8px 10px;
                                background: rgba(192, 57, 43, 0.12);
                                border-left: 3px solid #c0392b;
                                font-size: 13px;">
                        ${escapeHtml(err.message || 'Ошибка')}
                    </div>`;
            }
        } finally {
            wiwBusy = false;
            renderTab();
        }
    }

    async function doWiwTeardown() {
        if (wiwBusy) return;
        if (!confirm('Отключить WARP-in-WARP? Туннели, которые мы ' +
                     'поднимали для этого режима, будут опущены.')) {
            return;
        }
        wiwBusy = true;
        renderTab();
        try {
            const resp = await API.delete('/api/awg/warp-in-warp');
            if (!resp.ok) throw new Error(resp.error || 'Ошибка отключения');
            Toast.success('WARP-in-WARP отключён');
            await loadWiwData();
        } catch (err) {
            Toast.error(err.message || 'Ошибка');
        } finally {
            wiwBusy = false;
            renderTab();
        }
    }

    function formatBytes(n) {
        n = Number(n) || 0;
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
        return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    }

    function formatHandshake(ts) {
        const t = Number(ts) || 0;
        if (!t) return 'нет';
        const ago = Math.max(0, Math.floor(Date.now() / 1000) - t);
        if (ago < 60) return ago + ' с назад';
        if (ago < 3600) return Math.floor(ago / 60) + ' мин назад';
        if (ago < 86400) return Math.floor(ago / 3600) + ' ч назад';
        return Math.floor(ago / 86400) + ' д назад';
    }

    // ══════════════ events ══════════════

    function onTextInput() {
        const ta = document.getElementById('awg-warp-text');
        importText = ta ? ta.value : '';
    }

    function clearText() {
        importText = '';
        const ta = document.getElementById('awg-warp-text');
        if (ta) ta.value = '';
        const status = document.getElementById('awg-warp-import-status');
        if (status) status.innerHTML = '';
    }

    function onFile(event) {
        const file = event.target.files && event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result || '';
            importText = String(text);
            const ta = document.getElementById('awg-warp-text');
            if (ta) ta.value = importText;
            // Подставить дефолтное имя из имени файла
            const nameInp = document.getElementById('awg-warp-name');
            if (nameInp && !nameInp.value) {
                const base = file.name.replace(/\.conf$/i, '').slice(0, 15);
                if (base) nameInp.value = base;
            }
        };
        reader.readAsText(file);
        event.target.value = '';
    }

    async function doImport() {
        if (importing) return;
        if (!importText.trim()) {
            Toast.error('Вставьте конфиг или загрузите файл');
            return;
        }
        const nameInp = document.getElementById('awg-warp-name');
        const desiredName = nameInp ? nameInp.value.trim() : '';

        const status = document.getElementById('awg-warp-import-status');
        const btn = document.getElementById('awg-warp-import-btn');
        importing = true;
        if (btn) btn.disabled = true;
        if (status) status.innerHTML = `<span class="text-muted">Импорт...</span>`;

        try {
            const resp = await API.post('/api/awg/warp/import', {
                text: importText,
                name: desiredName || undefined,
            });
            if (!resp.ok) {
                throw new Error(resp.error || 'Ошибка импорта');
            }

            const warningsHtml = (resp.warnings && resp.warnings.length)
                ? `<div style="margin-top:8px; padding: 8px 10px;
                              background: var(--bg-warning, #5a4a1c);
                              border-left: 3px solid #d39e00;
                              font-size: 12px;">
                       <strong>Предупреждения:</strong>
                       <ul style="margin: 4px 0 0 18px;">
                          ${resp.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}
                       </ul>
                   </div>`
                : '';

            if (status) {
                status.innerHTML = `
                    <div style="padding: 8px 10px; background: rgba(46, 160, 67, 0.1);
                                border-left: 3px solid #2ea043; font-size: 13px;">
                        Конфиг сохранён как <strong>${escapeHtml(resp.name)}</strong>.
                        ${resp.is_warp ? 'Распознан как WARP.' : 'WARP-сигнатуры не обнаружены, но конфиг валиден.'}
                    </div>
                    ${warningsHtml}
                    <div style="margin-top: 10px; display:flex; gap:8px;">
                        <button class="btn btn-primary btn-sm"
                                onclick="window.location.hash='awg-configs?edit=${encodeURIComponent(resp.name)}'">
                            Открыть в редакторе
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="window.location.hash='awg'">
                            К туннелям
                        </button>
                        <button class="btn btn-ghost btn-sm"
                                onclick="AwgWarpPage.clearText()">
                            Импортировать ещё
                        </button>
                    </div>
                `;
            }
            Toast.success(`Импортирован ${resp.name}`);
        } catch (err) {
            if (status) {
                status.innerHTML = `
                    <div style="padding: 8px 10px; background: var(--bg-warning, #5a1c1c);
                                border-left: 3px solid #c0392b; font-size: 13px;">
                        ${escapeHtml(err.message || 'Ошибка импорта')}
                    </div>
                `;
            }
            Toast.error(err.message || 'Ошибка импорта');
        } finally {
            importing = false;
            if (btn) btn.disabled = false;
        }
    }

    // ══════════════ tab: Генерация ══════════════

    function onLicenseInput() {
        const inp = document.getElementById('awg-warp-license');
        genLicense = inp ? inp.value : '';
    }

    function onGenNameInput() {
        const inp = document.getElementById('awg-warp-gen-name');
        genName = inp ? inp.value : '';
    }

    async function doGenerate() {
        if (generating) return;

        const status = document.getElementById('awg-warp-gen-status');
        const btn    = document.getElementById('awg-warp-gen-btn');

        generating = true;
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Генерация...';
        }
        if (status) {
            status.innerHTML = `<span class="text-muted">
                Регистрация WARP-аккаунта в Cloudflare...
            </span>`;
        }

        try {
            const body = { save: false };
            if (genLicense.trim()) body.license_key = genLicense.trim();
            if (genName.trim())    body.name        = genName.trim();

            const resp = await API.post('/api/awg/warp/generate', body);
            if (!resp.ok) throw new Error(resp.error || 'Ошибка генерации');

            genResult = resp;
            if (status) status.innerHTML = '';
            // Перерисовать всю вкладку, чтобы показать превью
            renderTab();
            Toast.success('WARP-конфиг сгенерирован');
        } catch (err) {
            if (status) {
                status.innerHTML = `
                    <div style="padding: 8px 10px;
                                background: rgba(192, 57, 43, 0.12);
                                border-left: 3px solid #c0392b;
                                font-size: 13px;">
                        ${escapeHtml(err.message || 'Ошибка генерации')}
                    </div>
                `;
            }
            Toast.error(err.message || 'Ошибка генерации');
        } finally {
            generating = false;
            const b = document.getElementById('awg-warp-gen-btn');
            if (b) {
                b.disabled = false;
                b.textContent = 'Сгенерировать';
            }
        }
    }

    async function doSaveGenerated() {
        if (savingGen || !genResult) return;
        const nameInp = document.getElementById('awg-warp-gen-savename');
        const desiredName = nameInp ? nameInp.value.trim() : (genResult.name || '');

        const btn = document.getElementById('awg-warp-gen-save-btn');
        savingGen = true;
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Сохранение...';
        }

        try {
            const resp = await API.post('/api/awg/configs', {
                name: desiredName,
                text: genResult.text,
            });
            if (!resp.ok) throw new Error(resp.error || 'Ошибка сохранения');

            genResult = Object.assign({}, genResult, {
                saved: true,
                name:  desiredName,
            });
            renderTab();
            Toast.success(`Сохранён ${desiredName}`);
        } catch (err) {
            Toast.error(err.message || 'Ошибка сохранения');
        } finally {
            savingGen = false;
            const b = document.getElementById('awg-warp-gen-save-btn');
            if (b) {
                b.disabled = false;
                b.textContent = 'Сохранить конфиг';
            }
        }
    }

    function discardGenerated() {
        genResult = null;
        renderTab();
    }

    // ══════════════ helpers ══════════════

    function escapeHtml(s) {
        if (s === null || s === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(s);
        return div.innerHTML;
    }

    return {
        render, destroy,
        switchTab, onTextInput, onFile, doImport, clearText,
        onLicenseInput, onGenNameInput, doGenerate,
        doSaveGenerated, discardGenerated,
        // WARP-in-WARP
        onWiwOuterChange, onWiwInnerChange,
        doWiwSetup, doWiwTeardown, refreshWiw,
    };
})();
