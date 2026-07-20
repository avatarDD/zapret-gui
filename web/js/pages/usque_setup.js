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
    releaseLabel: (r) => {
        const date = (r.published_at || '').slice(0, 10);
        return r.tag + (r.prerelease ? ' (предрелиз)' : '')
            + (date ? ' — ' + date : '');
    },
});
