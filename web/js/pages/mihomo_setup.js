/**
 * mihomo_setup.js — установка mihomo (Clash.Meta).
 *
 * По образцу singbox_setup.js: проверяет окружение (платформа, TUN,
 * firewall, установленная версия), асинхронно подтягивает версию из
 * апстрим-релиза MetaCubeX/mihomo и позволяет установить/обновить/
 * удалить бинарь с прогрессом.
 *
 * Бэкенд — /api/mihomo/{environment,version,install,install/status,
 * uninstall}. У mihomo нет manifest-эндпоинта (бинарь берётся напрямую
 * из апстрима), поэтому архитектура определяется автоматически.
 *
 * Отображение версий — в одном стиле с sing-box и AWG: «установлено X /
 * в релизе Y», с нормализацией версии (v1.18.0 == 1.18.0 == 1.18.0-1).
 */

const MihomoSetupPage = (() => {

    let env = null;            // /api/mihomo/environment (быстро, локально)
    let version = null;        // /api/mihomo/version (installed + latest, сеть)
    let versionError = '';
    let latestState = 'idle';  // 'idle'|'loading'|'done' — проверка релиза (GitHub)
    let installState = { status: 'idle', progress: 0, message: '' };

    let pollTimer = null;

    // Нормализация версий — как в awg_setup.js. Апстрим тег `v1.18.0`,
    // `mihomo -v` → `1.18.0`, иногда суффикс сборки `-1`. Приводим к
    // одному виду, чтобы не показывать ложное «доступно обновление».
    const normalizeVer = v =>
        String(v || '').trim().replace(/^v/i, '').replace(/-\d+$/, '');
    const verEqual = (a, b) => normalizeVer(a) === normalizeVer(b);

    // ══════════════ render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">mihomo — установка</h1>
                    <p class="page-description">
                        Установка и обновление бинаря mihomo (Clash.Meta) из
                        апстрим-релизов MetaCubeX/mihomo.
                    </p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-ghost btn-sm" onclick="window.location.hash='mihomo'">
                        ← Инстансы
                    </button>
                    <button class="btn btn-ghost btn-sm" onclick="MihomoSetupPage.refresh()">
                        Обновить
                    </button>
                </div>
            </div>

            <div id="mh-setup-content"></div>
        `;
        refresh();
    }

    function destroy() {
        stopPolling();
    }

    // ══════════════ data ══════════════

    async function refresh() {
        // Шаг 1 — БЫСТРАЯ локальная часть (платформа/TUN/установленная
        // версия). Без сети, поэтому рисуем сразу и страница не «висит».
        try {
            env = await API.post('/api/mihomo/environment/refresh')
                           .catch(() => null);
        } catch (e) {
            // ignore
        }
        renderContent();

        // Шаг 2 — МЕДЛЕННАЯ часть (GitHub: версия в релизе). Грузим в
        // фоне и перерисовываем, когда придёт, чтобы запрос к сети (на
        // роутере он может тянуться десятки секунд) не блокировал открытие.
        loadLatest();
    }

    // Проверка «что в апстрим-релизе» — отдельно и асинхронно (см. refresh).
    async function loadLatest() {
        latestState = 'loading';
        renderContent();
        try {
            const verResp = await API.get('/api/mihomo/version').catch(() => null);
            if (verResp && verResp.ok) {
                version = verResp;
                versionError = '';
            } else {
                version = null;
                versionError = (verResp && verResp.error)
                               || 'Не удалось получить версию из релиза (нет сети/GitHub заблокирован)';
            }
        } catch (e) {
            version = null;
            versionError = e.message;
        } finally {
            latestState = 'done';
            renderContent();
        }
    }

    // ══════════════ poll install progress ══════════════

    function startPolling() {
        stopPolling();
        pollTimer = setInterval(async () => {
            try {
                const r = await API.get('/api/mihomo/install/status');
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
        const box = document.getElementById('mh-setup-content');
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

        const installedVer = bin.version
                             || (version && version.installed && version.installed.version)
                             || '';
        const latestVer = (version && version.latest && version.latest.version) || '';
        const latestTag = (version && version.latest && version.latest.tag) || '';
        // Обновление считаем сами, с нормализацией (как в AWG), а не
        // доверяем сырому сравнению строк бэкенда — иначе `v1.18.0` !=
        // `1.18.0` даёт фантомное обновление.
        const hasUpdate = installed && !!latestVer && !!installedVer
                          && !verEqual(installedVer, latestVer);

        const installInProgress = ['starting', 'manifest', 'downloading',
                                   'verifying', 'extracting', 'installing']
                                   .includes(installState.status);

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
                    mihomo
                    ${installed
                        ? '<span style="color:#39c45e; font-size:12px; margin-left:8px;">установлен</span>'
                        : '<span style="color:#e58; font-size:12px; margin-left:8px;">не установлен</span>'}
                </div>
                <div style="margin-top:8px; font-size:13px;">
                    ${installed ? `
                        <div>Версия: <strong>${escapeHtml(installedVer || '?')}</strong></div>
                        <div class="text-muted" style="font-size:11px;">
                            ${escapeHtml(bin.path || '')}
                        </div>` : ''}
                    ${latestState === 'loading' ? `
                        <div style="margin-top:4px;" class="text-muted">
                            В релизе: проверяю…
                            <span class="spinner spinner-inline"></span>
                        </div>`
                      : latestVer ? `
                        <div style="margin-top:4px;">
                            В релизе: <strong>${escapeHtml(latestVer)}</strong>
                            ${latestTag ? `<span class="text-muted" style="font-size:11px;">(${escapeHtml(latestTag)})</span>` : ''}
                            ${hasUpdate
                                ? '<span style="color:#fb8;">— доступно обновление</span>'
                                : (installed ? '<span style="color:#39c45e;">— актуально</span>' : '')}
                        </div>` : ''}
                    ${versionError && latestState === 'done' ? `
                        <div class="text-muted" style="color:#e58; font-size:11px; margin-top:4px;">
                            ${escapeHtml(versionError)}
                        </div>` : ''}
                </div>

                <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="btn btn-primary btn-sm" ${installInProgress?'disabled':''}
                            onclick="MihomoSetupPage.install()">
                        ${installed ? (hasUpdate ? 'Обновить' : 'Переустановить') : 'Установить'}
                    </button>
                    ${installed ? `
                    <button class="btn btn-ghost btn-sm" ${installInProgress?'disabled':''}
                            onclick="MihomoSetupPage.uninstall()">
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
                    ${!installed ? '<li>Скачать и установить mihomo (кнопка выше)</li>' : ''}
                </ul>
            </div>` : ''}
        `;
    }

    // ══════════════ actions ══════════════

    async function install() {
        installState = { status: 'starting', progress: 0,
                         message: 'Запуск установки' };
        renderContent();
        startPolling();
        try {
            const r = await API.post('/api/mihomo/install', {});
            if (r && r.ok && !r.in_progress) {
                Toast.success(`mihomo ${r.version || ''} установлен`);
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
        if (!confirm('Удалить mihomo?')) return;
        try {
            const r = await API.post('/api/mihomo/uninstall');
            if (r && r.ok) {
                Toast.success('mihomo удалён');
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

    return {
        render, destroy, refresh,
        install, uninstall,
    };
})();
