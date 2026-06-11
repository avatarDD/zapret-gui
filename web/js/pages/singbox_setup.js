/**
 * singbox_setup.js — установка sing-box.
 *
 * Тонкий адаптер над общим компонентом SetupUI (см.
 * components/setup_ui.js): окружение, версии «установлено/в релизе»,
 * установка/обновление/удаление с прогрессом.
 *
 * Специфика sing-box: manifest наших релизов (выбор архитектуры),
 * признак сборки с clash_api и предупреждение needs_reinstall — без
 * clash_api тестер серверов умеет только TCP.
 */

const SingboxSetupPage = SetupUI.create({
    globalName: 'SingboxSetupPage',
    bodyId: 'sb-setup-content',
    title: 'sing-box — установка',
    description: 'Установка и обновление бинаря sing-box из наших релизов.',
    backHash: 'singbox',
    backLabel: '← Инстансы',
    apiBase: '/api/singbox',
    binaryLabel: 'sing-box',
    fetchManifest: true,
    latestLabel: 'В нашем релизе',

    // Подпись релиза в селекте выбора версии (наши тэги singbox-bin-*).
    releaseLabel: (r) => {
        const date = (r.published_at || '').slice(0, 10);
        return (r.version ? 'v' + r.version : r.tag) + (date ? ' — ' + date : '');
    },

    // Какие архитектуры доступны в релизе (ручной выбор — режим эксперта).
    archsFromManifest: (manifest) =>
        Object.keys(((manifest || {}).sing_box || {}).binaries || {}).sort(),

    // «В релизе» — версия из manifest, фолбэк на /version.latest.
    latestInfo: (st) => {
        const sb = (st.manifest && st.manifest.sing_box) || {};
        return {
            version: sb.version
                || (st.version && st.version.latest && st.version.latest.version)
                || '',
            tag: '',
        };
    },

    // Строка про clash_api в карточке версии.
    versionExtraHtml: (vm) => vm.installed ? `
        <div style="margin-top:4px;">
            clash_api: ${vm.bin.has_clash_api
                ? '<span style="color:#39c45e;">включён</span>'
                : '<span style="color:#fb8;">нет</span> — тестер серверов работает только по TCP'}
        </div>` : '',

    // Бинарь собран без clash_api → версия может совпадать с релизом,
    // но переустановиться всё равно стоит — отдельное предупреждение.
    alertHtml: (vm) => {
        const v = vm.version || {};
        if (!v.needs_reinstall) return '';
        const reason = v.reinstall_reason
            || 'Тестер серверов сейчас отсеивает только по TCP (фаза e2e через движок недоступна).';
        return `
            <div class="alert alert-warning" style="margin-top:10px;">
                <div class="alert-title">Бинарь sing-box собран без clash_api</div>
                <p style="font-size:12px; margin:6px 0 0;">
                    ${SetupUI.esc(reason)}
                    Нажмите «${vm.hasUpdate ? 'Обновить' : 'Переустановить'}» ниже —
                    свежая сборка из нашего релиза включает clash_api.
                </p>
            </div>`;
    },
});
