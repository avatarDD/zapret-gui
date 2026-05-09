/**
 * awg_warp.js — Импорт и (в будущем) генерация AWG-WARP конфигов.
 *
 * Текущий промт реализует таб "Импорт". Табы "Генерация" и "WARP-in-WARP"
 * добавлены как заглушки и будут заполнены в следующих промтах.
 */

const AwgWarpPage = (() => {

    let activeTab = 'import';
    let importText = '';
    let importing = false;

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

    function destroy() {}

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
        renderTab();
    }

    function renderTab() {
        const box = document.getElementById('awg-warp-tab-content');
        if (!box) return;
        if (activeTab === 'import')   return renderImportTab(box);
        if (activeTab === 'generate') return renderGenerateStub(box);
        if (activeTab === 'wiw')      return renderWiwStub(box);
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

    function renderGenerateStub(box) {
        box.innerHTML = `
            <div class="text-muted" style="padding: 32px; text-align: center;">
                Нативная генерация WARP-конфигов появится в следующем обновлении.
                <br>Пока используйте таб «Импорт» или внешний генератор.
            </div>
        `;
    }

    function renderWiwStub(box) {
        box.innerHTML = `
            <div class="text-muted" style="padding: 32px; text-align: center;">
                WARP-in-WARP (двойной туннель) появится в следующем обновлении.
            </div>
        `;
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
    };
})();
