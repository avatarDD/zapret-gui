/**
 * expert.js — единый «режим эксперта» для всего GUI.
 *
 * Одна галка (внизу сайдбара) показывает/прячет продвинутые поля по
 * всему интерфейсу. По умолчанию режим ВЫКЛЮЧЕН — новичок видит только
 * необходимое, эксперт включает расширенный режим галкой.
 *
 * Хранится в localStorage (preference устройства, как тема) — применяется
 * мгновенно и не зависит от настроек бэкенда/бэкапа.
 *
 * Механика — чисто CSS, без перерисовок страниц:
 *   - body.expert-mode выставляется этим модулем;
 *   - элементы с классом .expert-only видны ТОЛЬКО в режиме эксперта;
 *   - элементы с классом .expert-note (подсказки «здесь скрыты
 *     расширенные настройки») видны ТОЛЬКО в простом режиме.
 *
 * Использование на страницах:
 *   <div class="expert-only">…продвинутые поля…</div>
 *   ${Expert.noteHtml('Скрыты расширенные поля')}   // подсказка
 */
const Expert = (() => {
    const KEY = 'zapret-gui-expert';

    function enabled() {
        try { return localStorage.getItem(KEY) === '1'; }
        catch (_) { return false; }
    }

    function apply(on) {
        document.body.classList.toggle('expert-mode', !!on);
        syncToggle(on);
        // Страницам, которым CSS недостаточно (перестроение форм и т.п.)
        try {
            document.dispatchEvent(new CustomEvent('expert-changed',
                                                   { detail: { enabled: !!on } }));
        } catch (_) {}
    }

    function set(on) {
        try { localStorage.setItem(KEY, on ? '1' : '0'); } catch (_) {}
        apply(on);
    }

    function toggle() { set(!enabled()); }

    /** Подсказка для простого режима: «тут есть скрытые поля». */
    function noteHtml(text) {
        const t = text || 'Часть расширенных настроек скрыта';
        return `<div class="expert-note">${t} — включите режим
                «эксперт» (галка внизу меню слева).</div>`;
    }

    function syncToggle(on) {
        const cb = document.querySelector('#expert-toggle input');
        if (cb) cb.checked = !!on;
    }

    function init() {
        apply(enabled());
    }

    return { enabled, set, toggle, init, noteHtml };
})();
