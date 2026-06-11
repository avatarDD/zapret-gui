/**
 * setup_ui.js — переиспользуемый раздел «Установка» бинаря.
 *
 * Один компонент вместо копипасты singbox_setup/mihomo_setup: карточка
 * «Окружение» (платформа/TUN/firewall), карточка бинаря с версиями
 * «установлено X / в релизе Y» (нормализация v1.2.3 == 1.2.3 == 1.2.3-1,
 * как в awg_setup), кнопки установить/обновить/удалить с прогрессом.
 *
 * Открытие раздела НЕ блокируется сетью: сначала рисуется быстрая
 * локальная часть (environment), версия из релиза подтягивается фоном
 * с индикатором «проверяю…».
 *
 * Использование (страница — тонкий адаптер):
 *   const SingboxSetupPage = SetupUI.create({
 *       globalName: 'SingboxSetupPage',   // для inline-onclick
 *       bodyId:     'sb-setup-content',
 *       title:      'sing-box — установка',
 *       description:'…',
 *       backHash:   'singbox', backLabel: '← Инстансы',
 *       apiBase:    '/api/singbox',
 *       binaryLabel:'sing-box',
 *       fetchManifest: true,                  // есть ли GET <api>/manifest
 *       archsFromManifest(manifest) -> [..],  // выбор архитектуры (опц.)
 *       latestInfo(state) -> {version, tag},  // откуда брать «в релизе»
 *       versionExtraHtml(vm) -> html,         // доп. строки в карточке
 *       alertHtml(vm) -> html,                // доп. предупреждение
 *   });
 *
 * Бэкенд-контракт (одинаковый у sing-box и mihomo):
 *   POST <api>/environment/refresh, GET <api>/version,
 *   POST <api>/install, GET <api>/install/status, POST <api>/uninstall.
 */
const SetupUI = (() => {

    // Нормализация версий — как в awg_setup.js: тег `v1.18.0`,
    // бинарь — `1.18.0`, пакет — `1.18.0-1`. Сравниваем приведённые,
    // чтобы не показывать фантомное «доступно обновление».
    const normalizeVer = v =>
        String(v || '').trim().replace(/^v/i, '').replace(/-\d+$/, '');
    const verEqual = (a, b) => normalizeVer(a) === normalizeVer(b);

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }

    /** Карточка «Окружение» — платформа / TUN / firewall. */
    function environmentCardHtml(env) {
        const platform = (env && env.platform) || {};
        const tun      = (env && env.tun) || {};
        return `
            <div class="card" style="margin-bottom:12px;">
                <div class="card-title">Окружение</div>
                <div style="display:grid; grid-template-columns: 1fr 2fr; gap:6px 16px;
                            font-size:13px; margin-top:8px;">
                    <div class="text-muted">Платформа:</div>
                    <div><strong>${esc(platform.kind || platform.name || '?')}</strong>
                         <span class="text-muted expert-only" style="font-size:11px;">
                           (binary_dir: ${esc(platform.binary_dir || '')})
                         </span></div>
                    <div class="text-muted">TUN:</div>
                    <div>${tun.available
                            ? '<span style="color:#39c45e;">доступен</span>'
                            : '<span style="color:#e58;">недоступен</span> — нужна установка TUN-компонента'}
                    </div>
                    <div class="text-muted">Firewall:</div>
                    <div>${esc(platform.firewall_backend || 'unknown')}</div>
                </div>
            </div>`;
    }

    /** Полоса прогресса установки (общая для всех установщиков). */
    function progressHtml(installState) {
        const st = installState || {};
        const active = ['starting', 'manifest', 'downloading', 'verifying',
                        'extracting', 'installing', 'done', 'error']
                        .includes(st.status);
        if (!active) return '';
        return `<div style="margin-top:12px;">
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                <span>${esc(st.message || st.status)}</span>
                <span class="text-muted">${st.progress || 0}%</span>
            </div>
            <div style="background:var(--bg-secondary); height:6px; border-radius:3px; overflow:hidden;">
                <div style="background:${st.status === 'error' ? '#e58' : '#39c45e'};
                            height:100%; width:${st.progress || 0}%;
                            transition: width 0.3s;"></div>
            </div>
          </div>`;
    }

    function create(opts) {
        const st = {
            env: null,
            version: null,        // GET <api>/version (installed + latest)
            versionError: '',
            manifest: null,       // GET <api>/manifest (если fetchManifest)
            manifestError: '',
            latestState: 'idle',  // 'idle'|'loading'|'done' — фоновая проверка релиза
            installState: { status: 'idle', progress: 0, message: '' },
            archOverride: '',
        };
        let pollTimer = null;

        // ══════════════ render ══════════════

        function render(container) {
            container.innerHTML = `
                <div class="page-header">
                    <div>
                        <h1 class="page-title">${esc(opts.title)}</h1>
                        <p class="page-description">${opts.description || ''}</p>
                    </div>
                    <div style="display:flex; gap:8px;">
                        ${opts.backHash ? `
                        <button class="btn btn-ghost btn-sm"
                                onclick="window.location.hash='${escAttr(opts.backHash)}'">
                            ${esc(opts.backLabel || '← Назад')}
                        </button>` : ''}
                        <button class="btn btn-ghost btn-sm" onclick="${opts.globalName}.refresh()">
                            Обновить
                        </button>
                    </div>
                </div>

                <div id="${opts.bodyId}"></div>
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
                st.env = await API.post(`${opts.apiBase}/environment/refresh`)
                                  .catch(() => null);
            } catch (e) { /* ignore */ }
            renderContent();

            // Шаг 2 — МЕДЛЕННАЯ часть (GitHub: версия в релизе/manifest).
            // Грузим в фоне и перерисовываем, когда придёт, чтобы запрос к
            // сети (на роутере может тянуться десятки секунд) не блокировал
            // открытие раздела.
            loadLatest();
        }

        async function loadLatest() {
            st.latestState = 'loading';
            renderContent();
            try {
                const wants = [API.get(`${opts.apiBase}/version`).catch(() => null)];
                if (opts.fetchManifest) {
                    wants.push(API.get(`${opts.apiBase}/manifest`).catch(() => null));
                }
                const [verResp, manResp] = await Promise.all(wants);

                if (verResp && verResp.ok !== false) {
                    st.version = verResp;
                    st.versionError = '';
                } else {
                    st.version = verResp || null;
                    st.versionError = (verResp && verResp.error)
                        || 'Не удалось получить версию из релиза (нет сети/GitHub заблокирован)';
                }
                if (opts.fetchManifest) {
                    if (manResp && manResp.ok) {
                        st.manifest = manResp.manifest;
                        st.manifestError = '';
                    } else {
                        st.manifest = null;
                        st.manifestError = (manResp && manResp.error)
                            || 'Не удалось получить manifest (нет сети/релиза)';
                    }
                }
            } catch (e) {
                st.versionError = e.message;
            } finally {
                st.latestState = 'done';
                renderContent();
            }
        }

        // ══════════════ poll install progress ══════════════

        function startPolling() {
            stopPolling();
            pollTimer = setInterval(async () => {
                try {
                    const r = await API.get(`${opts.apiBase}/install/status`);
                    if (r && r.progress) {
                        st.installState = r.progress;
                        renderContent();
                        if (st.installState.status === 'done' ||
                            st.installState.status === 'error') {
                            stopPolling();
                            setTimeout(refresh, 500);   // перечитать environment
                        }
                    }
                } catch (_) {}
            }, 800);
        }
        function stopPolling() {
            if (pollTimer) clearInterval(pollTimer);
            pollTimer = null;
        }

        // ══════════════ view-model ══════════════

        function viewModel() {
            const env = st.env || {};
            const bin = env.binary || {};
            const installed = !!bin.installed;
            const installedVer = bin.version
                || (st.version && st.version.installed && st.version.installed.version)
                || '';
            const latest = opts.latestInfo
                ? (opts.latestInfo(st) || {})
                : {
                    version: (st.version && st.version.latest && st.version.latest.version) || '',
                    tag:     (st.version && st.version.latest && st.version.latest.tag) || '',
                  };
            // Обновление считаем сами, с нормализацией (как в AWG), а не
            // сырым сравнением строк — иначе `v1.18.0` != `1.18.0` даёт
            // фантомное «доступно обновление».
            const hasUpdate = installed && !!latest.version && !!installedVer
                              && !verEqual(installedVer, latest.version);
            return {
                env, bin, installed, installedVer,
                latestVer: latest.version || '', latestTag: latest.tag || '',
                hasUpdate,
                version: st.version, manifest: st.manifest,
            };
        }

        // ══════════════ render content ══════════════

        function renderContent() {
            const box = document.getElementById(opts.bodyId);
            if (!box) return;

            if (!st.env) {
                box.innerHTML = `<div class="card">
                    <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
                </div>`;
                return;
            }

            const vm = viewModel();
            const env = vm.env;
            const tun = env.tun || {};
            const ready = !!env.ready;
            const installed = vm.installed;

            const archs = opts.archsFromManifest
                ? (opts.archsFromManifest(st.manifest) || [])
                : [];

            const installInProgress = ['starting', 'manifest', 'downloading',
                                       'verifying', 'extracting', 'installing']
                                       .includes(st.installState.status);

            // Ручной выбор архитектуры — продвинутое (режим эксперта):
            // нужен только когда автоопределение ошиблось (Exec format error).
            const archSelect = archs.length ? `
                <div class="expert-only">
                    <label class="form-label" style="margin-top:8px;">
                        Архитектура (авто — пусто):
                    </label>
                    <select id="${opts.bodyId}-arch" class="form-input"
                            onchange="${opts.globalName}.onArchChange()">
                        <option value="">авто</option>
                        ${archs.map(a =>
                            `<option value="${escAttr(a)}" ${a === st.archOverride ? 'selected' : ''}>${esc(a)}</option>`
                        ).join('')}
                    </select>
                </div>
                ${Expert.noteHtml('Ручной выбор архитектуры скрыт')}` : '';

            const errors = [...new Set(
                [st.versionError, st.manifestError].filter(Boolean))];

            const latestLabel = opts.latestLabel || 'В релизе';

            box.innerHTML = `
                ${environmentCardHtml(env)}

                <div class="card" style="margin-bottom:12px;">
                    <div class="card-title">
                        ${esc(opts.binaryLabel)}
                        ${installed
                            ? '<span style="color:#39c45e; font-size:12px; margin-left:8px;">установлен</span>'
                            : '<span style="color:#e58; font-size:12px; margin-left:8px;">не установлен</span>'}
                    </div>
                    <div style="margin-top:8px; font-size:13px;">
                        ${installed ? `
                            <div>Версия: <strong>${esc(vm.installedVer || '?')}</strong></div>
                            <div class="text-muted" style="font-size:11px;">
                                ${esc(vm.bin.path || '')}
                            </div>` : ''}
                        ${st.latestState === 'loading' ? `
                            <div style="margin-top:4px;" class="text-muted">
                                ${latestLabel}: проверяю…
                                <span class="spinner spinner-inline"></span>
                            </div>`
                          : vm.latestVer ? `
                            <div style="margin-top:4px;">
                                ${latestLabel}: <strong>${esc(vm.latestVer)}</strong>
                                ${vm.latestTag ? `<span class="text-muted" style="font-size:11px;">(${esc(vm.latestTag)})</span>` : ''}
                                ${vm.hasUpdate
                                    ? '<span style="color:#fb8;">— доступно обновление</span>'
                                    : (installed ? '<span style="color:#39c45e;">— актуально</span>' : '')}
                            </div>` : ''}
                        ${opts.versionExtraHtml ? (opts.versionExtraHtml(vm) || '') : ''}
                        ${st.latestState === 'done' && errors.length ? errors.map(e => `
                            <div class="text-muted" style="color:#e58; font-size:11px; margin-top:4px;">
                                ${esc(e)}
                            </div>`).join('') : ''}
                    </div>

                    ${opts.alertHtml ? (opts.alertHtml(vm) || '') : ''}

                    ${archSelect}

                    <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
                        <button class="btn btn-primary btn-sm" ${installInProgress ? 'disabled' : ''}
                                onclick="${opts.globalName}.install()">
                            ${installed ? (vm.hasUpdate ? 'Обновить' : 'Переустановить') : 'Установить'}
                        </button>
                        ${installed ? `
                        <button class="btn btn-ghost btn-sm" ${installInProgress ? 'disabled' : ''}
                                onclick="${opts.globalName}.uninstall()">
                            Удалить
                        </button>` : ''}
                    </div>

                    ${progressHtml(st.installState)}
                </div>

                ${!ready && !installed ? `
                <div class="alert alert-warning">
                    <div class="alert-title">Что нужно для запуска</div>
                    <ul style="margin:6px 0 0; padding-left:18px; font-size:12px;">
                        ${!tun.available ? '<li>Установить TUN-компонент (см. AmneziaWG → Установка — компонент одинаковый)</li>' : ''}
                        ${!installed ? `<li>Скачать и установить ${esc(opts.binaryLabel)} (кнопка выше)</li>` : ''}
                    </ul>
                </div>` : ''}
            `;
        }

        function onArchChange() {
            const el = document.getElementById(`${opts.bodyId}-arch`);
            if (el) st.archOverride = el.value;
        }

        // ══════════════ actions ══════════════

        async function install() {
            st.installState = { status: 'starting', progress: 0,
                                message: 'Запуск установки' };
            renderContent();
            startPolling();
            try {
                const body = opts.installPayload
                    ? (opts.installPayload(st) || {})
                    : (st.archOverride ? { arch: st.archOverride } : {});
                const r = await API.post(`${opts.apiBase}/install`, body);
                if (r && r.ok && !r.in_progress) {
                    Toast.success(`${opts.binaryLabel} ${r.version || ''} установлен`);
                } else if (r && r.in_progress) {
                    // Поллер сам подберёт прогресс
                } else if (r && r.error) {
                    Toast.error(r.error);
                }
            } catch (e) {
                Toast.error(e.message);
            }
        }

        async function uninstall() {
            if (!confirm(`Удалить ${opts.binaryLabel}?`)) return;
            try {
                const r = await API.post(`${opts.apiBase}/uninstall`);
                if (r && r.ok) {
                    Toast.success(`${opts.binaryLabel} удалён`);
                } else {
                    Toast.error((r && r.error) || 'failed');
                }
            } catch (e) {
                Toast.error(e.message);
            }
            await refresh();
        }

        return {
            render, destroy, refresh,
            install, uninstall, onArchChange,
        };
    }

    return { create, environmentCardHtml, progressHtml,
             normalizeVer, verEqual, esc, escAttr };
})();
