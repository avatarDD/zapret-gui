/**
 * usque_setup.js — Страница установки/обновления usque-keenetic.
 */

const UsqueSetupPage = SetupUI.create({
    globalName: 'UsqueSetupPage',
    bodyId: 'usque-setup-content',
    title: 'usque-keenetic — установка',
    description: 'Установка и обновление бинарника usque-keenetic для обхода DPI через MASQUE-протокол.',
    backHash: 'warp-in-warp',
    backLabel: '← WARP-in-WARP',
    apiBase: '/api/usque',
    helpTopic: 'usque-install',
    binaryLabel: 'usque',
    fetchManifest: false,
    latestLabel: 'В релизе',
    // «Версия» в карточке — это тег ПАКЕТА usque-keenetic (v0.3.0), он и
    // сравнивается с «В релизе». Версия самого движка usque (4.2.0) живёт
    // в своём пространстве нумерации, сравнивать их между собой нельзя —
    // раньше из-за этого всегда горело «доступно обновление».
    versionExtraHtml: (vm) => {
        const eng = (vm.bin && vm.bin.engine_version) || '';
        if (!eng) return '';
        return `<div class="detail-row">Движок usque: <strong>${eng}</strong></div>`;
    },
    releaseLabel: (r) => {
        const date = (r.published_at || '').slice(0, 10);
        return r.tag + (r.prerelease ? ' (предрелиз)' : '')
            + (date ? ' — ' + date : '');
    },
});
