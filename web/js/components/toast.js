/**
 * toast.js — Всплывающие уведомления.
 *
 * Использование:
 *   Toast.success('nfqws2 запущен');
 *   Toast.error('Ошибка запуска');
 *   Toast.warning('Процесс не найден');
 *   Toast.info('Стратегия применена');
 *
 * MR-115: поддержка max-limit (5 тостов) и дедупликации (тот же
 * type+message в течение 2 с подавляется).
 */

const Toast = (() => {
    const ICONS = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
        error:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    const DURATION = 4000;
    const MAX_TOASTS = 5;      // MR-115: не более 5 тостов одновременно
    const DEDUP_MS  = 2000;    // MR-115: тот же type+message — игнор в течение 2 с

    // MR-115: счётчик активных и история для дедупликации
    let _activeCount = 0;
    const _recentKeys = new Map(); // "type:message" -> timestamp

    function show(type, message, duration = DURATION) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        // MR-67: Убедимся, что контейнер доступен для чтения скринридерами
        if (!container.hasAttribute('aria-live')) {
            container.setAttribute('aria-live', 'polite');
        }

        // MR-115: дедупликация
        const key = type + ':' + message;
        const now = Date.now();
        const lastSeen = _recentKeys.get(key);
        if (lastSeen && (now - lastSeen) < DEDUP_MS) return;
        _recentKeys.set(key, now);
        // Чистим устаревшие ключи
        for (const [k, ts] of _recentKeys) {
            if (now - ts > DEDUP_MS * 4) _recentKeys.delete(k);
        }

        // MR-115: при превышении лимита — удаляем самый старый тост
        if (_activeCount >= MAX_TOASTS) {
            const oldest = container.querySelector('.toast');
            if (oldest) _remove(oldest);
        }

        const el = document.createElement('div');
        el.className = `toast ${type}`;

        // MR-67: Размечаем роль в зависимости от типа
        if (type === 'error' || type === 'warning') {
            el.setAttribute('role', 'alert');
        } else {
            el.setAttribute('role', 'status');
        }

        el.innerHTML = `
            <span class="toast-icon">${ICONS[type] || ICONS.info}</span>
            <span class="toast-text">${escapeHtml(message)}</span>
        `;

        container.appendChild(el);
        _activeCount++;

        // Автоудаление
        const timer = setTimeout(() => _remove(el), duration);

        // Клик для закрытия
        el.addEventListener('click', () => {
            clearTimeout(timer);
            _remove(el);
        });
    }

    function _remove(el) {
        if (!el.isConnected) return;
        el.classList.add('removing');
        _activeCount = Math.max(0, _activeCount - 1);
        el.addEventListener('animationend', () => el.remove(), { once: true });
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
