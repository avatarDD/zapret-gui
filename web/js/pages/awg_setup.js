/**
 * awg_setup.js — Setup-wizard для AmneziaWG.
 *
 * Шаги:
 *   1. Детект окружения (платформа, архитектура, что найдено)
 *   2. Prerequisites (TUN, OpkgTun на Keenetic)
 *   3. Установка бинарников из релизов с прогрессом
 *   4. Готово
 */

const AwgSetupPage = (() => {

    let env = null;          // отчёт /api/awg/environment
    let manifest = null;     // /api/awg/manifest
    let manifestError = null; // диагностика ошибки manifest
    let manifestRepo = '';
    let installState = null; // /api/awg/install/status

    let pollTimer = null;
    let installRunning = false;
    let currentStep = 1;

    // ══════════════ Render ══════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">AmneziaWG — установка</h1>
                    <p class="page-description">
                        Подготовка роутера к работе с AmneziaWG: проверка окружения и установка бинарников.
                    </p>
                </div>
                <button class="btn btn-ghost btn-sm" onclick="AwgSetupPage.refresh()" id="awg-btn-refresh">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                    </svg>
                    Проверить заново
                </button>
            </div>

            <!-- Шаги мастера -->
            <div class="card" style="margin-bottom: 16px; padding: 12px 16px;">
                <div id="awg-stepper" style="display:flex; gap: 8px; flex-wrap: wrap;
                                              align-items: center; font-size: 13px;">
                    <span class="awg-step" data-step="1">1. Окружение</span>
                    <span style="color: var(--text-muted);">→</span>
                    <span class="awg-step" data-step="2">2. Prerequisites</span>
                    <span style="color: var(--text-muted);">→</span>
                    <span class="awg-step" data-step="3">3. Установка</span>
                    <span style="color: var(--text-muted);">→</span>
                    <span class="awg-step" data-step="4">4. Готово</span>
                </div>
            </div>

            <!-- Шаг 1: окружение -->
            <div class="card" id="awg-step-env" style="margin-bottom: 16px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                        <line x1="8" y1="21" x2="16" y2="21"/>
                        <line x1="12" y1="17" x2="12" y2="21"/>
                    </svg>
                    Шаг 1. Окружение
                </div>
                <div id="awg-env-body" style="margin-top: 10px;">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>
            </div>

            <!-- Шаг 2: prerequisites -->
            <div class="card" id="awg-step-prereq" style="margin-bottom: 16px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M9 11l3 3L22 4"/>
                        <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                    </svg>
                    Шаг 2. Prerequisites
                </div>
                <div id="awg-prereq-body" style="margin-top: 10px;"></div>
            </div>

            <!-- Шаг 3: установка -->
            <div class="card" id="awg-step-install" style="margin-bottom: 16px;">
                <div class="card-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Шаг 3. Установка бинарников
                </div>
                <div id="awg-install-body" style="margin-top: 10px;"></div>
            </div>

            <!-- Шаг 4: готово -->
            <div class="card hidden" id="awg-step-done" style="margin-bottom: 16px;
                                                              border-left: 3px solid var(--success);">
                <div class="card-title" style="color: var(--success);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    Шаг 4. Готово
                </div>
                <div id="awg-done-body" style="margin-top: 10px; font-size: 13px; color: var(--text-secondary);">
                    AWG установлен и готов к настройке. Создание интерфейсов и WARP появятся в следующих обновлениях.
                </div>
            </div>

            <style>
                .awg-step {
                    padding: 4px 10px;
                    border-radius: 12px;
                    background: var(--bg-input);
                    color: var(--text-secondary);
                    border: 1px solid transparent;
                }
                .awg-step.active {
                    background: rgba(99,102,241,0.15);
                    color: var(--primary);
                    border-color: rgba(99,102,241,0.3);
                    font-weight: 600;
                }
                .awg-step.done {
                    background: rgba(52,211,153,0.12);
                    color: var(--success);
                    border-color: rgba(52,211,153,0.3);
                }
                .awg-row {
                    display: flex;
                    align-items: flex-start;
                    gap: 10px;
                    padding: 10px 12px;
                    background: var(--bg-input);
                    border-radius: var(--radius-sm);
                    margin-bottom: 6px;
                    font-size: 13px;
                }
                .awg-row-icon {
                    width: 18px; height: 18px;
                    flex-shrink: 0;
                    display: flex; align-items: center; justify-content: center;
                    border-radius: 50%;
                    font-size: 12px; font-weight: 700;
                    margin-top: 1px;
                }
                .awg-row-icon.ok    { background: rgba(52,211,153,0.18); color: var(--success); }
                .awg-row-icon.bad   { background: rgba(248,113,113,0.18); color: var(--error); }
                .awg-row-icon.info  { background: rgba(99,102,241,0.18); color: var(--primary); }
                .awg-row-body { flex: 1; min-width: 0; }
                .awg-row-title { color: var(--text-primary); font-weight: 500; }
                .awg-row-detail {
                    color: var(--text-secondary);
                    font-size: 12px;
                    margin-top: 2px;
                    white-space: pre-wrap;
                    word-break: break-word;
                }
                .awg-mono {
                    font-family: var(--font-mono);
                    color: var(--text-primary);
                    font-size: 12px;
                }
                .awg-progress-track {
                    height: 8px;
                    background: var(--bg-input);
                    border-radius: 4px;
                    overflow: hidden;
                    margin-top: 6px;
                }
                .awg-progress-bar {
                    height: 100%;
                    background: linear-gradient(90deg, var(--primary), var(--accent));
                    transition: width 0.3s ease;
                }
            </style>
        `;
        loadAll();
    }

    // ══════════════ Loading ══════════════

    async function loadAll() {
        await Promise.all([loadEnv(), loadInstallStatus()]);
        // Manifest подтягиваем независимо — может ошибиться (нет интернета)
        loadManifest();
    }

    async function loadEnv() {
        try {
            env = await API.get('/api/awg/environment');
        } catch (err) {
            env = { ok: false, error: err.message };
        }
        renderEnv();
        renderPrereq();
        renderInstall();
        recomputeStep();
    }

    async function loadInstallStatus() {
        try {
            installState = await API.get('/api/awg/install/status');
        } catch (err) {
            installState = null;
        }
        renderInstall();
        recomputeStep();
    }

    async function loadManifest() {
        try {
            const r = await API.get('/api/awg/manifest');
            manifest = r && r.ok ? r.manifest : null;
            manifestError = r && !r.ok ? (r.error || 'unknown') : null;
            manifestRepo = (r && r.repo) || '';
        } catch (err) {
            manifest = null;
            manifestError = err && err.message ? err.message : String(err);
            manifestRepo = '';
        }
        renderInstall();
    }

    // ══════════════ Step 1: Environment ══════════════

    function renderEnv() {
        const body = document.getElementById('awg-env-body');
        if (!body) return;

        if (!env || !env.ok) {
            body.innerHTML = `
                <div class="awg-row">
                    <div class="awg-row-icon bad">!</div>
                    <div class="awg-row-body">
                        <div class="awg-row-title">Ошибка детекта</div>
                        <div class="awg-row-detail">${escapeHtml((env && env.error) || 'нет ответа от /api/awg/environment')}</div>
                    </div>
                </div>
            `;
            return;
        }

        const p = env.platform || {};
        const a = env.architecture || {};
        const ex = env.existing || {};

        const rows = [];
        rows.push(rowHtml('info', 'Платформа',
            `${p.name || '?'}${p.keenos_version ? ' · KeenOS ' + p.keenos_version : ''}`));
        rows.push(rowHtml('info', 'Архитектура',
            `${a.uname_m || '?'}${a.opkg_arch ? ' (opkg: ' + a.opkg_arch + ')' : ''} → <span class="awg-mono">${a.artifact_arch || '?'}</span>`));
        rows.push(rowHtml(
            ex.has_existing ? 'info' : 'ok',
            'Существующая установка AWG',
            ex.has_existing
                ? formatExisting(ex)
                : 'Не найдено — чистая установка.'
        ));
        rows.push(rowHtml('info', 'Каталог бинарников',
            `<span class="awg-mono">${escapeHtml(p.binary_dir || '')}</span>`));
        rows.push(rowHtml('info', 'Каталог конфигов',
            `<span class="awg-mono">${escapeHtml(p.config_dir || '')}</span>`));
        rows.push(rowHtml('info', 'Firewall',
            p.firewall_backend || 'неизвестно'));

        body.innerHTML = rows.join('');
    }

    function formatExisting(ex) {
        const parts = [];
        if (ex.binary_awg_go) parts.push('amneziawg-go: ' + ex.binary_awg_go);
        if (ex.binary_awg) parts.push('awg: ' + ex.binary_awg);
        if (ex.configs && ex.configs.length) {
            parts.push('конфиги: ' + ex.configs.map(c => c.name).join(', '));
        }
        if (ex.active_interfaces && ex.active_interfaces.length) {
            parts.push('активные ifaces: ' + ex.active_interfaces.map(i => i.name).join(', '));
        }
        return escapeHtml(parts.join('\n'));
    }

    // ══════════════ Step 2: Prerequisites ══════════════

    function renderPrereq() {
        const body = document.getElementById('awg-prereq-body');
        if (!body) return;

        if (!env || !env.ok) {
            body.innerHTML = `<div class="awg-row"><div class="awg-row-icon bad">!</div>
                <div class="awg-row-body"><div class="awg-row-title">Окружение не определено</div></div></div>`;
            return;
        }

        const items = (env.prerequisites && env.prerequisites.items) || [];
        if (!items.length) {
            body.innerHTML = `<div class="awg-row-detail">Нет требований к проверке.</div>`;
            return;
        }

        const html = items.map(i => {
            const cls = i.met ? 'ok' : (i.blocker ? 'bad' : 'info');
            const sym = i.met ? '✓' : (i.blocker ? '!' : '?');
            const detail = !i.met && i.hint
                ? `<div class="awg-row-detail">${escapeHtml(i.hint)}</div>`
                : '';
            return `
                <div class="awg-row">
                    <div class="awg-row-icon ${cls}">${sym}</div>
                    <div class="awg-row-body">
                        <div class="awg-row-title">${escapeHtml(i.label || i.id)}</div>
                        ${detail}
                    </div>
                </div>
            `;
        }).join('');

        const ready = env.ready;
        const summary = ready
            ? `<div class="awg-row" style="border-left: 3px solid var(--success); padding-left: 12px;">
                 <div class="awg-row-icon ok">✓</div>
                 <div class="awg-row-body"><div class="awg-row-title">Все условия выполнены — можно устанавливать.</div></div>
               </div>`
            : `<div class="awg-row" style="border-left: 3px solid var(--warning); padding-left: 12px;">
                 <div class="awg-row-icon bad">!</div>
                 <div class="awg-row-body">
                   <div class="awg-row-title">Не все условия выполнены</div>
                   <div class="awg-row-detail">Выполните инструкции выше и нажмите «Проверить заново».</div>
                 </div>
               </div>`;
        body.innerHTML = html + summary;
    }

    // ══════════════ Step 3: Install ══════════════

    function renderInstall() {
        const body = document.getElementById('awg-install-body');
        if (!body) return;

        const op = (installState && installState.operation) || {};
        const installed = (installState && installState.installed) || {};
        const target = (installState && installState.target) || {};
        const ready = env && env.ready;
        const arch = (env && env.architecture && env.architecture.artifact_arch) || '';

        const archs = manifest ? Object.keys(
            (manifest.amneziawg_go && manifest.amneziawg_go.binaries) || {}
        ) : [];

        const archSupported = !arch || !archs.length || archs.includes(arch);

        let manifestHtml = '';
        if (manifest) {
            const goVer = (manifest.amneziawg_go || {}).version || '?';
            const toolsVer = (manifest.amneziawg_tools || {}).version || '?';
            manifestHtml = rowHtml(
                'info', 'Доступная версия',
                `amneziawg-go <span class="awg-mono">${escapeHtml(goVer)}</span>, ` +
                `amneziawg-tools <span class="awg-mono">${escapeHtml(toolsVer)}</span>` +
                ` (релиз <span class="awg-mono">${escapeHtml(manifest.tag || '')}</span>)` +
                (archs.length ? `<br>Архитектуры: ${archs.map(a => `<span class="awg-mono">${a}</span>`).join(', ')}` : '')
            );
        } else {
            const repoLine = manifestRepo
                ? `Репозиторий: <span class="awg-mono">${escapeHtml(manifestRepo)}</span>.<br>`
                : '';
            const errLine = manifestError
                ? `Подробности: <span class="awg-mono">${escapeHtml(manifestError)}</span>`
                : 'Проверьте интернет на роутере и наличие релизов с префиксом awg-bin-* в репозитории.';
            manifestHtml = rowHtml(
                'bad', 'Manifest не загружен',
                repoLine + errLine
            );
        }

        // ── Установленная версия + детект обновления ─────────────
        const latestGo    = (manifest && manifest.amneziawg_go    && manifest.amneziawg_go.version)    || '';
        const latestTools = (manifest && manifest.amneziawg_tools && manifest.amneziawg_tools.version) || '';
        const latestTag   = (manifest && manifest.tag) || '';
        // opkg возвращает версии вроде `v0.2.16-1`, manifest — `0.2.18`.
        // Нормализуем перед сравнением, чтобы не считать `v0.2.18` !== `0.2.18`.
        const normalizeVer = v => String(v || '').trim().replace(/^v/i, '').replace(/-\d+$/, '');
        const verEqual = (a, b) => !a || !b || normalizeVer(a) === normalizeVer(b);
        const goOutdated    = !!(latestGo    && installed.go_version    && !verEqual(installed.go_version,    latestGo));
        const toolsOutdated = !!(latestTools && installed.tools_version && !verEqual(installed.tools_version, latestTools));
        const tagOutdated   = !!(latestTag   && installed.tag           && installed.tag !== latestTag);
        const updateAvailable = installed.installed && (goOutdated || toolsOutdated || tagOutdated);

        // Если для external-установки версии так и не определились (бинарь
        // не отвечает на --version), считаем что предложить переустановку
        // имеет смысл всегда — но без шильда "обновление".
        const versionsUnknown = installed.installed && installed.external &&
                                !installed.go_version && !installed.tools_version;

        function verCell(installedVer, latestVer, outdated, source) {
            const cur = installedVer || '?';
            const srcHint = source
                ? ` <span class="text-muted" style="font-size: 11px;">[${escapeHtml(source)}]</span>`
                : '';
            if (!latestVer) {
                return `<span class="awg-mono">${escapeHtml(cur)}</span>${srcHint}`;
            }
            if (outdated) {
                return `<span class="awg-mono">${escapeHtml(cur)}</span>${srcHint} ` +
                       `<span style="color: var(--warning);">→ ${escapeHtml(latestVer)}</span>`;
            }
            return `<span class="awg-mono">${escapeHtml(cur)}</span>${srcHint} ` +
                   `<span style="color: var(--success); font-size: 11px;">(актуально)</span>`;
        }

        let installedHtml = '';
        if (installed.installed) {
            let kind, title, detail;
            if (updateAvailable) {
                kind  = 'info';
                title = 'Доступно обновление';
            } else if (installed.external) {
                kind  = 'info';
                title = versionsUnknown ? 'Установка вне нашего GUI' : 'Установка вне нашего GUI (актуально)';
            } else {
                kind  = 'ok';
                title = 'Установлено и актуально';
            }

            const verLines =
                `amneziawg-go: ${verCell(installed.go_version, latestGo, goOutdated, installed.go_version_source)}<br>` +
                `amneziawg-tools: ${verCell(installed.tools_version, latestTools, toolsOutdated, installed.tools_version_source)}`;

            const tagLine = installed.tag
                ? `<br>Релиз: <span class="awg-mono">${escapeHtml(installed.tag)}</span>` +
                  (tagOutdated ? ` <span style="color: var(--warning);">→ ${escapeHtml(latestTag)}</span>` : '')
                : (latestTag ? `<br>Свежий релиз: <span class="awg-mono">${escapeHtml(latestTag)}</span>` : '');

            const pathLine = installed.external
                ? `<br>amneziawg-go: <span class="awg-mono">${escapeHtml(installed.amneziawg_go || '')}</span>` +
                  `<br>awg: <span class="awg-mono">${escapeHtml(installed.awg || '')}</span>` +
                  `<br><span class="text-muted" style="font-size: 11px;">GUI ещё не управляет этой установкой — после установки она перейдёт под управление.</span>`
                : `<br>Каталог: <span class="awg-mono">${escapeHtml(installed.binary_dir || '')}</span>`;

            detail = verLines + tagLine + pathLine;
            installedHtml = rowHtml(kind, title, detail);
        }

        // Куда поставим + warning'и
        let targetHtml = '';
        if (target.target_dir) {
            const platformDefault = target.platform_default || '';
            const usingExternal = target.target_source === 'external';
            const willOverwrite = target.will_overwrite || [];
            const outOfTarget = target.out_of_target || [];
            const dirNote = usingExternal
                ? ` <span style="color: var(--warning);">(подстраиваемся под существующую установку)</span>`
                : (target.target_dir !== platformDefault
                    ? ` <span style="color: var(--text-muted);">(из настроек)</span>`
                    : '');
            const overwriteNote = willOverwrite.length
                ? `<br><span style="color: var(--warning);">Будут перезаписаны:</span> ${willOverwrite.map(p => `<span class="awg-mono">${escapeHtml(p)}</span>`).join(', ')}`
                : '';
            const outNote = outOfTarget.length
                ? `<br><span style="color: var(--warning);">Останутся вне target — возможен конфликт PATH:</span> ${outOfTarget.map(p => `<span class="awg-mono">${escapeHtml(p)}</span>`).join(', ')}`
                : '';
            targetHtml = rowHtml(
                outOfTarget.length ? 'bad' : (usingExternal || willOverwrite.length ? 'info' : 'info'),
                'Каталог установки',
                `<span class="awg-mono">${escapeHtml(target.target_dir)}</span>${dirNote}` +
                overwriteNote + outNote
            );
        }

        // Активные интерфейсы — предупреждение
        let activeHtml = '';
        const active = (target.active_interfaces || []).filter(Boolean);
        if (active.length) {
            activeHtml = rowHtml(
                'info',
                'Запущенные AWG/WG интерфейсы',
                `${active.map(n => `<span class="awg-mono">${escapeHtml(n)}</span>`).join(', ')}<br>` +
                `После установки новых бинарников эти процессы продолжат работу со старым кодом. ` +
                `Чтобы переключить их на свежие бинарники, перейдите в ` +
                `<a href="#awg-dashboard" style="color: var(--primary);">AmneziaWG → туннели</a> ` +
                `и нажмите <strong>Restart</strong> на нужном туннеле.`
            );
        }

        let archHtml = '';
        if (arch && !archSupported && manifest) {
            archHtml = rowHtml(
                'bad', 'Архитектура не поддерживается',
                `${arch} нет в текущем релизе. Доступны: ${archs.join(', ')}.`
            );
        }

        // Прогресс
        let progressHtml = '';
        if (op.in_progress || installRunning) {
            const pct = Math.max(0, Math.min(100, op.progress || 0));
            progressHtml = `
                <div class="awg-row">
                    <div class="awg-row-icon info"><span class="spinner" style="width:14px;height:14px;border-width:2px;"></span></div>
                    <div class="awg-row-body">
                        <div class="awg-row-title">${escapeHtml(op.status || 'Установка...')}</div>
                        <div class="awg-progress-track"><div class="awg-progress-bar" style="width: ${pct}%;"></div></div>
                        <div class="awg-row-detail">${pct}%</div>
                    </div>
                </div>
            `;
        }

        // Кнопки
        const canInstall = ready && manifest && archSupported && !op.in_progress && !installRunning;
        let installLabel;
        if (!installed.installed) {
            installLabel = 'Установить';
        } else if (updateAvailable) {
            installLabel = latestTag
                ? `Обновить до ${latestTag}`
                : 'Обновить';
        } else {
            installLabel = 'Переустановить';
        }
        const installBtnClass = updateAvailable ? 'btn-primary' : 'btn-success';
        const buttonsHtml = `
            <div class="actions-row" style="margin-top: 10px;">
                <button class="btn ${installBtnClass}" id="awg-btn-install"
                        onclick="AwgSetupPage.doInstall()" ${canInstall ? '' : 'disabled'}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    ${installLabel}
                </button>
                ${installed.installed ? `
                    <button class="btn btn-danger" onclick="AwgSetupPage.doUninstall()"
                            ${(op.in_progress || installRunning) ? 'disabled' : ''}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                        </svg>
                        Удалить
                    </button>
                ` : ''}
            </div>
        `;

        body.innerHTML = installedHtml + manifestHtml + targetHtml + activeHtml +
                          archHtml + progressHtml + buttonsHtml;
    }

    // ══════════════ Stepper state ══════════════

    function recomputeStep() {
        const ready = !!(env && env.ready);
        const installed = !!(installState && installState.installed && installState.installed.installed);
        const op = (installState && installState.operation) || {};

        let step = 1;
        if (env && env.ok) step = 2;
        if (env && env.ok && ready) step = 3;
        if (op.in_progress) step = 3;
        if (installed) step = 4;
        currentStep = step;

        // Покажем «Готово»
        const done = document.getElementById('awg-step-done');
        if (done) done.classList.toggle('hidden', !installed);

        // Обновим стилизацию шагов
        document.querySelectorAll('.awg-step').forEach(el => {
            const n = parseInt(el.dataset.step, 10);
            el.classList.toggle('active', n === currentStep);
            el.classList.toggle('done', n < currentStep);
        });
    }

    // ══════════════ Actions ══════════════

    async function refresh() {
        try {
            env = await API.post('/api/awg/environment/refresh', {});
        } catch (e) {
            Toast.error('Ошибка детекта: ' + e.message);
        }
        renderEnv();
        renderPrereq();
        renderInstall();
        await loadInstallStatus();
        loadManifest();
    }

    async function doInstall() {
        if (installRunning) return;

        // Подтверждение если есть внешняя установка / активные интерфейсы
        const target = (installState && installState.target) || {};
        const willOverwrite = target.will_overwrite || [];
        const outOfTarget = target.out_of_target || [];
        const active = (target.active_interfaces || []).filter(Boolean);
        const lines = [];
        if (willOverwrite.length) {
            lines.push('Будут перезаписаны существующие бинари:\n  ' + willOverwrite.join('\n  '));
        }
        if (outOfTarget.length) {
            lines.push('Останутся в других каталогах (потенциальный конфликт PATH):\n  ' + outOfTarget.join('\n  '));
        }
        if (active.length) {
            lines.push('Запущенные интерфейсы — после установки перезапустите вручную:\n  ' + active.join(', '));
        }
        if (lines.length) {
            const ok = confirm('Внимание:\n\n' + lines.join('\n\n') +
                               '\n\nПродолжить установку?');
            if (!ok) return;
        }

        installRunning = true;
        renderInstall();
        startPoll();
        try {
            const r = await API.post('/api/awg/install', {});
            if (r.in_progress) {
                Toast.info('Установка запущена');
            } else if (r.ok) {
                Toast.success(r.message || 'Установлено');
                installRunning = false;
                stopPoll();
                await loadInstallStatus();
                await loadEnv();
            } else {
                Toast.error(r.message || 'Ошибка установки');
                installRunning = false;
                stopPoll();
                await loadInstallStatus();
            }
        } catch (e) {
            Toast.error('Ошибка: ' + e.message);
            installRunning = false;
            stopPoll();
            await loadInstallStatus();
        }
    }

    async function doUninstall() {
        if (!confirm('Удалить бинарники AmneziaWG?')) return;
        try {
            const r = await API.post('/api/awg/uninstall', {});
            if (r.ok) {
                Toast.success(r.message || 'Удалено');
            } else {
                Toast.error(r.message || 'Ошибка удаления');
            }
        } catch (e) {
            Toast.error('Ошибка: ' + e.message);
        }
        await loadInstallStatus();
        await loadEnv();
    }

    function startPoll() {
        stopPoll();
        pollTimer = setInterval(async () => {
            await loadInstallStatus();
            const op = (installState && installState.operation) || {};
            if (!op.in_progress) {
                installRunning = false;
                stopPoll();
                await loadEnv();
            }
        }, 1500);
    }

    function stopPoll() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // ══════════════ Helpers ══════════════

    function rowHtml(kind, title, detail) {
        const sym = kind === 'ok' ? '✓' : (kind === 'bad' ? '!' : 'i');
        return `
            <div class="awg-row">
                <div class="awg-row-icon ${kind}">${sym}</div>
                <div class="awg-row-body">
                    <div class="awg-row-title">${escapeHtml(title)}</div>
                    <div class="awg-row-detail">${detail}</div>
                </div>
            </div>
        `;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = (text === null || text === undefined) ? '' : String(text);
        return div.innerHTML;
    }

    function destroy() {
        stopPoll();
        env = null;
        manifest = null;
        installState = null;
    }

    return {
        render,
        destroy,
        refresh,
        doInstall,
        doUninstall,
    };
})();
