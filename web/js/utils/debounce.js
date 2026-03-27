/**
 * debounce.js — Утилиты для оптимизации частых вызовов.
 *
 * Debounce — задержка выполнения до окончания серии вызовов.
 * Throttle — ограничение частоты выполнения.
 */

const Utils = (() => {

    /**
     * Debounce: вызывает fn через delay мс после последнего вызова.
     * @param {Function} fn
     * @param {number} delay — задержка в мс (default: 300)
     * @returns {Function}
     */
    function debounce(fn, delay = 300) {
        let timer = null;
        return function (...args) {
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                timer = null;
                fn.apply(this, args);
            }, delay);
        };
    }

    /**
     * Throttle: вызывает fn не чаще чем раз в interval мс.
     * @param {Function} fn
     * @param {number} interval — минимальный интервал в мс (default: 1000)
     * @returns {Function}
     */
    function throttle(fn, interval = 1000) {
        let lastTime = 0;
        let timer = null;
        return function (...args) {
            const now = Date.now();
            const remaining = interval - (now - lastTime);
            if (remaining <= 0) {
                if (timer) { clearTimeout(timer); timer = null; }
                lastTime = now;
                fn.apply(this, args);
            } else if (!timer) {
                timer = setTimeout(() => {
                    timer = null;
                    lastTime = Date.now();
                    fn.apply(this, args);
                }, remaining);
            }
        };
    }

    /**
     * Lazy load: загружает JS-страницу при первом обращении.
     * Для будущего использования с динамическим import.
     */
    function lazyPage(loader) {
        let module = null;
        let loading = false;
        let pending = [];

        return {
            render(container) {
                if (module) {
                    module.render(container);
                    return;
                }
                container.innerHTML = '<div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>';
                if (loading) {
                    pending.push(container);
                    return;
                }
                loading = true;
                loader().then(m => {
                    module = m;
                    loading = false;
                    module.render(container);
                    pending.forEach(c => module.render(c));
                    pending = [];
                }).catch(err => {
                    loading = false;
                    container.innerHTML = '<div class="card" style="padding:24px;text-align:center;color:var(--error);">Ошибка загрузки: ' + err.message + '</div>';
                });
            },
            destroy() {
                if (module && module.destroy) module.destroy();
            }
        };
    }

    return { debounce, throttle, lazyPage };
})();
