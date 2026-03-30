const Utils = (() => {
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
