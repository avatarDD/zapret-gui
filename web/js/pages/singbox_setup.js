/**
 * singbox_setup.js — установка sing-box.
 *
 * Проверяет окружение (платформа, TUN, версия sing-box если уже
 * установлен), показывает manifest последнего релиза и позволяет
 * установить/обновить/удалить sing-box-бинарь.
 */

const SingboxSetupPage = (() => {

    let env = null;
    let manifest = null;
    let manifestError = '';
    let version = null;        // /api/singbox/version (installed + latest)
    let installState = { status: 'idle', progress: 0, message: '' };

    let pollTimer = null;
    let archOverride = '';

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">sing-box — установка</h1>
                    <p class="page-description">
                        Установка и обновление бинаря sing-box из наших релизов.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='singbox'">
                        ← Инстансы
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="SingboxSetupPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div id="sb-setup-content"></div>
        `;
        refresh();
    }

    function destroy() {
        stopPolling();
    }

    // ══════════════ data ══════════════

    async function refresh() {
        try {
            const [envResp, verResp] = await Promise.all([
                API.post('/api/singbox/environment/refresh').catch(() => null),
                API.get('/api/singbox/version').catch(() => null),
            ]);
            env     = envResp || null;
            version = verResp || null;
        } catch (e) {
            // ignore
        }

        // Manifest опционально — если нет интернета или нет релиза
        try {
            const r = await API.get('/api/singbox/manifest');
            if (r && r.ok) {
                manifest = r.manifest;
                manifestError = '';
            } else {
                manifest = null;
                manifestError = (r && r.error) || 'Не удалось получить manifest';
            }
        } catch (e) {
            manifest = null;
            manifestError = e.message;
        }

        renderContent();
    }

    // ══════════════ poll install progress ══════════════

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(async () => {
            try {
                const r = await API.get('/api/singbox/install/status');
                if (r && r.progress) {
                    installState = r.progress;
                    renderContent();
                    if (installState.status === 'done' ||
                        installState.status === 'error') {
                        stopPolling();
                        // Перечитываем environment
                        setTimeout(refresh, 500);
                    }
                }
            } catch (_) {}
        }, 800);
    }
    function stopPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    // ══════════════ render ══════════════

    function renderContent() {
        const box = document.getElementById('sb-setup-content');
        if (!box) return;

        if (!env) {
            box.innerHTML = `<div class="card">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>`;
            return;
        }

        const platform = env.platform || {};
        const bin      = env.binary   || {};
        const tun      = env.tun      || {};
        const ready    = !!env.ready;
        const installed = !!bin.installed;

        // Какие архитектуры доступны в релизе
        const sb = (manifest && manifest.sing_box) || {};
        const availableArchs = Object.keys(sb.binaries || {}).sort();
        const latestVersion  = sb.version || (version && version.latest && version.latest.version) || '';
        const hasUpdate = !!(version && version.has_update);

        const installInProgress = ['starting', 'manifest', 'downloading',
                                   'verifying', 'extracting', 'installing']
                                   .includes(installState.status);

        const archSelect = availableArchs.length ? `
            <label class="form-label" style="margin-top:8px;">
                Архитектура (авто — пусто):
            </label>
            <select id="sb-arch" class="form-input"
                    onchange="SingboxSetupPage.onArchChange()">
                <option value="">авто</option>
                ${availableArchs.map(a =>
                    `<option value="${escapeAttr(a)}" ${a===archOverride?'selected':''}>${escapeHtml(a)}</option>`
                ).join('')}
            </select>` : '';

        const progressBlock = (installInProgress || installState.status === 'done'
                                || installState.status === 'error')
            ? `<div style="margin-top:12px;">
                <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                    <span>${escapeHtml(installState.message || installState.status)}</span>
                    <span class="text-muted">${installState.progress || 0}%</span>
                </div>
                <div style="background:var(--bg-secondary); height:6px; border-radius:3px; overflow:hidden;">
                    <div style="background:${installState.status==='error'?'#e58':'#39c45e'};
                                height:100%; width:${installState.progress || 0}%;
                                transition: width 0.3s;"></div>
                </div>
              </div>`
            : '';

        box.innerHTML = `
            <div class="card" style="margin-bottom:12px;">
                <div class="card-title">Окружение</div>
                <div style="display:grid; grid-template-columns: 1fr 2fr; gap:6px 16px;
                            font-size:13px; margin-top:8px;">
                    <div class="text-muted">Платформа:</div>
                    <div><strong>${escapeHtml(platform.kind || platform.name || '?')}</strong>
                         <span class="text-muted" style="font-size:11px;">
                           (binary_dir: ${escapeHtml(platform.binary_dir || '')})
                         </span></div>
                    <div class="text-muted">TUN:</div>
                    <div>${tun.available
                            ? '<span style="color:#39c45e;">доступен</span>'
                            : '<span style="color:#e58;">недоступен</span> — нужна установка TUN-компонента'}
                    </div>
                    <div class="text-muted">Firewall:</div>
                    <div>${escapeHtml(platform.firewall_backend || 'unknown')}</div>
                </div>
            </div>

            <div class="card" style="margin-bottom:12px;">
                <div class="card-title">
                    sing-box
                    ${installed
                        ? '<span style="color:#39c45e; font-size:12px; margin-left:8px;">установлен</span>'
                        : '<span style="color:#e58; font-size:12px; margin-left:8px;">не установлен</span>'}
                </div>
                <div style="margin-top:8px; font-size:13px;">
                    ${installed ? `
                        <div>Версия: <strong>${escapeHtml(bin.version || '?')}</strong></div>
                        <div class="text-muted" style="font-size:11px;">
                            ${escapeHtml(bin.path || '')}
                        </div>` : ''}
                    ${latestVersion ? `
                        <div style="margin-top:4px;">
                            В нашем релизе: <strong>${escapeHtml(latestVersion)}</strong>
                            ${hasUpdate ? '<span style="color:#fb8;">— доступно обновление</span>' : ''}
                        </div>` : ''}
                    ${manifestError ? `
                        <div class="text-muted" style="color:#e58; font-size:11px; margin-top:4px;">
                            ${escapeHtml(manifestError)}
                        </div>` : ''}
                </div>

                ${archSelect}

                <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-primary btn-sm" ${installInProgress?'disabled':''}
                            onclick="SingboxSetupPage.install()">
                        ${installed ? (hasUpdate ? 'Обновить' : 'Переустановить') : 'Установить'}
                    </button>
                    ${installed ? `
                    <button class="btn btn-ghost btn-sm" ${installInProgress?'disabled':''}
                            onclick="SingboxSetupPage.uninstall()">
                        Удалить
                    </button>` : ''}
                </div>

                ${progressBlock}
            </div>

            ${!ready && !installed ? `
            <div class="alert alert-warning">
                <div class="alert-title">Что нужно для запуска</div>
                <ul style="margin:6px 0 0; padding-left:18px; font-size:12px;">
                    ${!tun.available ? '<li>Установить TUN-компонент (см. AmneziaWG → Установка — компонент одинаковый)</li>' : ''}
                    ${!installed ? '<li>Скачать и установить sing-box (кнопка выше)</li>' : ''}
                </ul>
            </div>` : ''}
        `;
    }

    function onArchChange() {
        const el = document.getElementById('sb-arch');
        if (el) archOverride = el.value;
    }

    // ══════════════ actions ══════════════

    async function install() {
        installState = { status: 'starting', progress: 0,
                         message: 'Запуск установки' };
        renderContent();
        startPolling();
        try {
            const r = await API.post('/api/singbox/install', {
                arch: archOverride || undefined,
            });
            if (r && r.ok) {
                Toast.success(`sing-box ${r.version || ''} установлен`);
            } else if (r && r.in_progress) {
                // Поллер сам подберёт
            } else if (r && r.error) {
                Toast.error(r.error);
            }
        } catch (e) {
            Toast.error(e.message);
        }
    }

    async function uninstall() {
        if (!confirm('Удалить sing-box?')) return;
        try {
            const r = await API.post('/api/singbox/uninstall');
            if (r && r.ok) {
                Toast.success('sing-box удалён');
            } else {
                Toast.error((r && r.error) || 'failed');
            }
        } catch (e) {
            Toast.error(e.message);
        }
        await refresh();
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escapeAttr(s) {
        return escapeHtml(s).replace(/"/g, '&quot;');
    }

    return {
        render, destroy, refresh,
        install, uninstall, onArchChange,
    };
})();
