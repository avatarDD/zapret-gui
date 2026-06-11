/**
 * mihomo_setup.js — установка mihomo (Clash.Meta).
 *
 * Тонкий адаптер над общим компонентом SetupUI (см.
 * components/setup_ui.js) — тот же раздел, что у sing-box: окружение,
 * версии «установлено/в релизе» (с нормализацией v1.18.0 == 1.18.0),
 * установка/обновление/удаление с прогрессом.
 *
 * Специфика mihomo: manifest-эндпоинта нет (бинарь берётся напрямую из
 * апстрим-релизов MetaCubeX/mihomo), архитектура определяется
 * автоматически, «в релизе» показываем с upstream-тегом.
 */

const MihomoSetupPage = SetupUI.create({
    globalName: 'MihomoSetupPage',
    bodyId: 'mh-setup-content',
    title: 'mihomo — установка',
    description: 'Установка и обновление бинаря mihomo (Clash.Meta) из ' +
                 'апстрим-релизов MetaCubeX/mihomo.',
    backHash: 'mihomo',
    backLabel: '← Инстансы',
    apiBase: '/api/mihomo',
    binaryLabel: 'mihomo',
    fetchManifest: false,
    latestLabel: 'В релизе',
});
