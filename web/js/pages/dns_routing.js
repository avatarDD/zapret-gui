/**
 * dns_routing.js — Per-domain DNS routing.
 *
 * Кастомный DNS для конкретных хостов (обход DNS-подмены ISP).
 */

const DnsRoutingPage = (() => {
    let _rules = [];
    let _servers = [];

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Per-domain DNS</h1>
                <span class="page-subtitle">Кастомный DNS для конкретных хостов</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Добавить правило</div>
                    <div class="card-body">
                        <div class="form-grid" style="grid-template-columns: 1fr 1fr auto;">
                            <div class="form-group">
                                <label>Домен</label>
                                <input type="text" id="dns-domain" class="form-control"
                                       placeholder="youtube.com">
                            </div>
                            <div class="form-group">
                                <label>DNS-сервер</label>
                                <select id="dns-server" class="form-control">
                                    <option value="">— загрузка...</option>
                                </select>
                            </div>
                            <div class="form-group" style="align-self:end;">
                                <button class="btn btn-primary" onclick="DnsRoutingPage.addRule()">Добавить</button>
                            </div>
                        </div>
                        <div class="text-muted" style="font-size:12px;">
                            Пример: youtube.com → Cloudflare (1.1.1.1) для обхода DNS-подмены ISP
                        </div>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title" style="display:flex; justify-content:space-between;">
                        <span>Правила</span>
                        <button class="btn btn-primary btn-sm" onclick="DnsRoutingPage.applyRules()">Применить (dnsmasq)</button>
                    </div>
                    <div class="card-body" id="dns-rules">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Быстрые пресеты</div>
                    <div class="card-body">
                        <div style="display:flex; flex-wrap:wrap; gap:6px;">
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('youtube.com','cloudflare')">YouTube → Cloudflare</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('google.com','google')">Google → Google DNS</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('telegram.org','cloudflare')">Telegram → Cloudflare</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('discord.com','cloudflare')">Discord → Cloudflare</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('t.me','cloudflare')">t.me → Cloudflare</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('facebook.com','cloudflare')">Facebook → Cloudflare</button>
                            <button class="btn btn-ghost btn-sm" onclick="DnsRoutingPage.addPreset('instagram.com','cloudflare')">Instagram → Cloudflare</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        await _refresh();
    }

    function destroy() {}

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

    function _renderRules() {
        const el = document.getElementById("dns-rules");
        if (!el) return;

        if (!_rules.length) {
            el.innerHTML = `<p class="text-muted">Нет правил. Добавьте домен выше или используйте пресеты.</p>`;
            return;
        }

        let html = '<table class="table"><thead><tr>';
        html += '<th>Домен</th><th>DNS</th><th>Описание</th><th></th>';
        html += '</tr></thead><tbody>';
        for (const r of _rules) {
            html += `<tr>
                <td><code>${esc(r.domain)}</code></td>
                <td>${esc(r.dns)}</td>
                <td class="text-muted">${esc(r.description || "")}</td>
                <td><button class="btn btn-danger btn-sm" onclick="DnsRoutingPage.removeRule('${esc(r.domain)}')">Удалить</button></td>
            </tr>`;
        }
        html += '</tbody></table>';
        el.innerHTML = html;
    }

    function _renderServers() {
        const sel = document.getElementById("dns-server");
        if (!sel) return;
        sel.innerHTML = _servers.map(s =>
            `<option value="${esc(s.id)}">${esc(s.name)} (${esc(s.ip)})</option>`
        ).join('');
    }

    async function addRule() {
        const domain = document.getElementById("dns-domain")?.value.trim();
        const dns = document.getElementById("dns-server")?.value;
        if (!domain || !dns) {
            Toast.error("Укажите домен и DNS-сервер");
            return;
        }
        try {
            const res = await API.post("/api/dns-routing/rules", { domain, dns });
            if (res.ok) {
                Toast.success("Правило добавлено");
                document.getElementById("dns-domain").value = "";
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function addPreset(domain, dns) {
        try {
            const res = await API.post("/api/dns-routing/rules", {
                domain, dns, description: "Быстрый пресет"
            });
            if (res.ok) {
                Toast.success(domain + " → " + dns);
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function removeRule(domain) {
        try {
            const res = await API.delete("/api/dns-routing/rules/" + encodeURIComponent(domain));
            if (res.ok) {
                Toast.success("Правило удалено");
                await _refresh();
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    async function applyRules() {
        try {
            const res = await API.post("/api/dns-routing/apply");
            if (res.ok) {
                Toast.success("Применено " + (res.applied || 0) + " правил → " + (res.file || "dnsmasq"));
            } else {
                Toast.error(res.error || "Ошибка");
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, addRule, addPreset, removeRule, applyRules };
})();
