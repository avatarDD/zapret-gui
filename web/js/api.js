/**
 * api.js — HTTP-клиент для взаимодействия с backend API.
 *
 * Использование:
 *   const status = await API.get('/api/status');
 *   await API.post('/api/start', { strategy_id: 'tcp_1' });
 */

const API = (() => {
    const BASE = '';  // Тот же origin

    async function request(method, path, body = null) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };

        if (body !== null && method !== 'GET') {
            opts.body = JSON.stringify(body);
        }

        try {
            const resp = await fetch(BASE + path, opts);
            const data = await resp.json();

            if (!resp.ok) {
                const msg = data.error || `HTTP ${resp.status}`;
                throw new Error(msg);
            }

            return data;
        } catch (err) {
            if (err.name === 'TypeError') {
                // Сетевая ошибка (сервер недоступен)
                throw new Error('Сервер недоступен');
            }
            throw err;
        }
    }

    return {
        get:    (path) =>         request('GET', path),
        post:   (path, body) =>   request('POST', path, body),
        put:    (path, body) =>   request('PUT', path, body),
        delete: (path, body) =>   request('DELETE', path, body),
    };
})();


