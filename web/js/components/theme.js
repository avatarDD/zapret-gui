/**
 * theme.js — переключение темы интерфейса (тёмная / светлая).
 *
 * Тема хранится в localStorage (preference устройства, не в settings.json
 * — чтобы применяться мгновенно, без обращения к API, и не зависеть от
 * бэкапа/восстановления). Атрибут data-theme на <html> переключает набор
 * CSS-переменных (см. [data-theme="light"] в style.css).
 *
 * Раннее применение (до первой отрисовки, без «вспышки») делает inline-
 * скрипт в <head> index.html. Этот модуль — управление из UI.
 */
const Theme = (() => {
    const KEY = 'zapret-gui-theme';
    const THEMES = ['dark', 'light'];
    const META_COLOR = { dark: '#0f1117', light: '#f5f6f8' };

    function get() {
        try {
            const t = localStorage.getItem(KEY);
            return THEMES.includes(t) ? t : 'dark';
        } catch (_) { return 'dark'; }
    }

    function apply(theme) {
        const t = THEMES.includes(theme) ? theme : 'dark';
        document.documentElement.setAttribute('data-theme', t);
        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.setAttribute('content', META_COLOR[t]);
        updateToggle(t);
    }

    function set(theme) {
        const t = THEMES.includes(theme) ? theme : 'dark';
        try { localStorage.setItem(KEY, t); } catch (_) {}
        apply(t);
    }

    function toggle() {
        set(get() === 'dark' ? 'light' : 'dark');
    }

    // Иконка/подпись кнопки-переключателя в сайдбаре.
    function updateToggle(theme) {
        const btn = document.getElementById('theme-toggle');
        if (!btn) return;
        const toLight = theme === 'dark';   // сейчас тёмная → кнопка ведёт в светлую
        btn.title = toLight ? 'Светлая тема' : 'Тёмная тема';
        btn.setAttribute('aria-label', btn.title);
        btn.innerHTML = toLight
            // солнце (переключить на светлую)
            ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
            // луна (переключить на тёмную)
            : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    }

    function init() {
        apply(get());
    }

    return { get, set, apply, toggle, init };
})();
