/**
 * dns_routing.js — DNS для отдельных доменов (per-domain DNS).
 *
 * Правило «домен → DNS-сервер» превращается в `server=/домен/IP` для
 * dnsmasq. Применяется сразу после добавления и удаления: раньше правило
 * лежало в настройках, пока не нажата отдельная кнопка «Применить», и
 * удалённое правило продолжало действовать.
 */

const DnsRoutingPage = (() => {
    let _rules = [];
    let _servers = [];
    let _lastError = '';

    const PRESETS = [
        ['youtube.com', 'cloudflare', 'YouTube'],
        ['googlevideo.com', 'cloudflare', 'Видео YouTube'],
        ['instagram.com', 'cloudflare', 'Instagram'],
        ['facebook.com', 'cloudflare', 'Facebook'],
        ['x.com', 'cloudflare', 'X / Twitter'],
        ['discord.com', 'cloudflare', 'Discord'],
        ['telegram.org', 'cloudflare', 'Telegram'],
        ['t.me', 'cloudflare', 't.me'],
    ];

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1 class="page-title">DNS для отдельных доменов${typeof Help !== 'undefined' ? Help.button('dns-routing') : ''}</h1>
                <p class="page-description">
                    Спрашивать адрес выбранных сайтов не у провайдера, а у
                    другого DNS-сервера. Помогает, когда провайдер подменяет
                    ответ DNS (сайт резолвится в заглушку или не резолвится).
                </p>
            </div>

            <div class="card">
                <div class="card-title">Добавить правило</div>
                <div class="dr-form">
                    <input type="text" id="dns-domain" class="form-control"
                           placeholder="Домен, например youtube.com" spellcheck="false">
                    <select id="dns-server" class="form-control">
                        <option value="">— загрузка...</option>
                    </select>
                    <button id="dr-add-rule-btn" class="btn btn-primary">Добавить</button>
                </div>
                <div class="dr-presets">
                    <span class="text-muted" style="font-size:12px;">Быстро через Cloudflare:</span>
                    ${PRESETS.map(([d, s, label]) =>
                        `<button class="btn-chip" data-preset-domain="${esc(d)}" data-dns="${esc(s)}">${esc(label)}</button>`
                    ).join('')}
                </div>
                <p class="form-hint" style="margin-top:10px;">
                    Поддомены входят в правило автоматически. Запрос уходит
                    обычным DNS (порт 53) на выбранный сервер: если провайдер
                    перехватывает весь DNS, это не поможет — тогда сайт нужно
                    пустить через туннель (раздел «Маршрутизация»).
                </p>
            </div>

            <div class="card">
                <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                    <span>Правила</span>
                    <button id="dr-apply-btn" class="btn btn-ghost btn-sm"
                            title="Записать правила в dnsmasq ещё раз">Применить заново</button>
                </div>
                <div id="dns-rules">Загрузка...</div>
            </div>
        `;

        bindEvents(container);
        await _refresh();
    }

    function destroy() {}

    function bindEvents(container) {
        document.getElementById("dr-add-rule-btn")?.addEventListener("click", addRule);
        document.getElementById("dr-apply-btn")?.addEventListener("click", () => applyRules(true));
        document.getElementById("dns-domain")?.addEventListener("keydown", e => {
            if (e.key === 'Enter') addRule();
        });

        container.addEventListener("click", e => {
            const preset = e.target.closest("[data-preset-domain]");
            if (preset) { addPreset(preset.dataset.presetDomain, preset.dataset.dns); return; }
            const del = e.target.closest("[data-remove-domain]");
            if (del) removeRule(del.dataset.removeDomain);
        });
    }

    async function _refresh() {
        try {
            const [rulesData, serversData] = await Promise.all([
                API.get("/api/dns-routing/rules"),
                API.get("/api/dns-routing/servers"),
            ]);
            _rules = rulesData.rules || [];
            _servers = serversData.servers || [];
            _renderRules();
            _renderServers();
        } catch (e) {
            const el = document.getElementById("dns-rules");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    function serverLabel(id) {
        const s = _servers.find(x => x.id === id);
        if (s) return `${s.name} (${s.ip})`;
        return id;
    }

    function _renderRules() {
        const el = document.getElementById("dns-rules");
        if (!el) return;

        const warn = _lastError
            ? `<div class="form-hint" style="color:var(--warning); margin-bottom:8px;">${esc(_lastError)}</div>`
            : '';
        if (!_rules.length) {
            el.innerHTML = warn + `<p class="text-muted">Правил нет. Добавьте домен выше.</p>`;
            return;
        }

        el.innerHTML = warn + `<div class="dr-list">${_rules.map(r => `
            <div class="dr-row">
                <code class="dr-domain">${esc(r.domain)}</code>
                <span class="dr-arrow">→</span>
                <span class="dr-server">${esc(serverLabel(r.dns))}</span>
                <button class="btn btn-ghost btn-sm dr-del" title="Удалить правило"
                        data-remove-domain="${esc(r.domain)}">✕</button>
            </div>`).join('')}</div>`;
    }

    function _renderServers() {
        const sel = document.getElementById("dns-server");
        if (!sel) return;
        sel.innerHTML = _servers.map(s =>
            `<option value="${esc(s.id)}">${esc(s.name)} (${esc(s.ip)})</option>`
        ).join('');
    }

    async function _post(domain, dns, description) {
        const res = await API.post("/api/dns-routing/rules",
                                   { domain, dns, description: description || '' });
        if (!res.ok) { Toast.error(res.error || "Ошибка"); return false; }
        await applyRules(false);
        await _refresh();
        return true;
    }

    async function addRule() {
        const input = document.getElementById("dns-domain");
        const domain = (input?.value || '').trim().toLowerCase()
            .replace(/^https?:\/\//, '').split('/')[0];
        const dns = document.getElementById("dns-server")?.value;
        if (!domain || !dns) {
            Toast.error("Укажите домен и DNS-сервер");
            return;
        }
        try {
            if (await _post(domain, dns)) {
                Toast.success(domain + " → " + serverLabel(dns));
                if (input) input.value = "";
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function addPreset(domain, dns) {
        try {
            if (await _post(domain, dns, "Быстрый пресет")) {
                Toast.success(domain + " → " + serverLabel(dns));
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function removeRule(domain) {
        try {
            const res = await API.delete("/api/dns-routing/rules/" + encodeURIComponent(domain));
            if (res.ok) {
                await applyRules(false);
                Toast.success("Правило удалено");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    /**
     * Записать правила в dnsmasq. `loud` — нажата кнопка (показать итог);
     * после добавления/удаления сообщаем только о проблеме.
     */
    async function applyRules(loud) {
        try {
            const res = await API.post("/api/dns-routing/apply");
            if (res.ok) {
                _lastError = '';
                if (loud) Toast.success("Применено правил: " + (res.applied || 0));
            } else {
                // Правило сохранено, но включить его некому (нет dnsmasq и
                // т.п.) — причина должна остаться на виду, а не в тосте.
                _lastError = res.error || "Правила сохранены, но не применены";
                Toast.warning(res.dnsmasq_found === false
                    ? "dnsmasq не найден — правила сохранены, но не действуют"
                    : _lastError);
            }
        } catch (e) {
            _lastError = e.message;
            Toast.error("Ошибка: " + e.message);
        }
        _renderRules();
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s == null ? '' : String(s);
        return d.innerHTML.replace(/"/g, '&quot;');
    }

    return { render, destroy, addRule, addPreset, removeRule, applyRules };
})();
