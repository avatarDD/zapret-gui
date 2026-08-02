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
    // «Версия» и «В релизе» — обе про сам usque: мы собираем его сами, и
    // тэг сборки (usque-bin-v4.2.1) кодирует ровно его версию. Раньше
    // «В релизе» брался из тэга стороннего пакета (v0.3.0), сравнивался
    // с версией движка (4.2.0) и вечно показывал «доступно обновление».
    versionExtraHtml: (vm) => {
        const tag = (vm.bin && vm.bin.tag) || '';
        if (!tag) return '';
        return `<div class="detail-row">Сборка: <code>${tag}</code></div>`;
    },
    releaseLabel: (r) => {
        const date = (r.published_at || '').slice(0, 10);
        return r.tag + (r.prerelease ? ' (предрелиз)' : '')
            + (date ? ' — ' + date : '');
    },
});
