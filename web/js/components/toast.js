/**
 * toast.js — Всплывающие уведомления.
 *
 * Использование:
 *   Toast.success('nfqws2 запущен');
 *   Toast.error('Ошибка запуска');
 *   Toast.warning('Процесс не найден');
 *   Toast.info('Стратегия применена');
 */

const Toast = (() => {
    const ICONS = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        error:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    const DURATION = 4000;

    function show(type, message, duration = DURATION) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.innerHTML = `
            <span class="toast-icon">${ICONS[type] || ICONS.info}</span>
            <span class="toast-text">${escapeHtml(message)}</span>
        `;

        container.appendChild(el);

        // Автоудаление
        const timer = setTimeout(() => remove(el), duration);

        // Клик для закрытия
        el.addEventListener('click', () => {
            clearTimeout(timer);
            remove(el);
        });
    }

    function remove(el) {
        el.classList.add('removing');
        el.addEventListener('animationend', () => el.remove());
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    return {
        success: (msg, dur) => show('success', msg, dur),
        error:   (msg, dur) => show('error', msg, dur),
        warning: (msg, dur) => show('warning', msg, dur),
        info:    (msg, dur) => show('info', msg, dur),
    };
})();



