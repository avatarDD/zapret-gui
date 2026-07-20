/**
 * tunnel_optimizer.js — Оптимизации латентности туннелей.
 *
 * MTU, safe TCP buffer floors and optional BBR.
 * Три профиля: low_latency, balanced, throughput.
 */

const TunnelOptimizerPage = (() => {
    let _status = null;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Оптимизации туннелей</h1>
                <span class="page-subtitle">MTU, безопасные TCP buffers, BBR</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Профиль</div>
                    <div class="card-body" id="opt-profile"></div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Текущие TCP-настройки</div>
                    <div class="card-body" id="opt-status">Загрузка...</div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Применить оптимизации</div>
                    <div class="card-body" id="opt-apply"></div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Сравнение профилей</div>
                    <div class="card-body">
                        <table class="table">
                            <thead><tr>
                                <th>Параметр</th>
                                <th>low_latency</th>
                                <th>balanced</th>
                                <th>throughput</th>
                            </tr></thead>
                            <tbody>
                                <tr><td>MTU</td><td>1280</td><td>1420</td><td>1420</td></tr>
                                <tr><td>TCP buffers</td><td>не уменьшаются</td><td>минимум 1 MB</td><td>минимум 4 MB</td></tr>
                                <tr><td>BBR</td><td colspan="3">✅ Включён (все профили)</td></tr>
                                <tr><td>TCP Fast Open</td><td colspan="3">⚠️ только если поддержан приложением</td></tr>
                                <tr><td>TCP_NODELAY</td><td colspan="3">⚠️ задаётся приложением</td></tr>
                                <tr><td>Keepalive</td><td colspan="3">не меняется глобально</td></tr>
                                <tr><td>Лучше для</td><td>Gaming, VoIP</td><td>Общий случай</td><td>Загрузки</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;

        await _refresh();
    }

    function destroy() {}

    async function _refresh() {
        await Promise.all([_loadStatus(), _renderProfile()]);
    }

    async function _loadStatus() {
        try {
            const data = await API.get("/api/optimizer/status");
            _status = data.status || data || {};
            const el = document.getElementById("opt-status");
            if (!el) return;

            let html = '<table class="table"><tbody>';
            const fields = {
                "tcp_congestion_control": "Congestion control",
                "tcp_fastopen": "TCP Fast Open",
                "tcp_keepalive_time": "Keepalive time (s)",
                "available_cc": "Доступные CC",
            };
            for (const [key, label] of Object.entries(fields)) {
                const val = _status[key] || "—";
                const isGood = _isGoodValue(key, val);
                html += `<tr>
                    <td>${label}</td>
                    <td><code>${esc(val)}</code></td>
                    <td>${isGood ? '<span style="color:var(--success);">✅</span>' : '<span style="color:var(--warning);">⚠️</span>'}</td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;
        } catch (e) {
            const el = document.getElementById("opt-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    function _isGoodValue(key, val) {
        if (key === "tcp_congestion_control") return val.includes("bbr");
        if (key === "tcp_fastopen") return val === "3" || val === "1" || val === "2";
        if (key === "tcp_keepalive_time") return parseInt(val) >= 30;
        return true;
    }

    async function _renderProfile() {
        const el = document.getElementById("opt-profile");
        if (!el) return;

        el.innerHTML = `
            <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                <select id="opt-profile-select" class="form-control" style="max-width:200px;">
                    <option value="low_latency">Low Latency (gaming/VoIP)</option>
                    <option value="balanced" selected>Balanced (общий)</option>
                    <option value="throughput">Throughput (загрузки)</option>
                </select>
                <button class="btn btn-primary" id="opt-apply-btn"
                        onclick="TunnelOptimizerPage.applyAll()">Применить ко всем туннелям</button>
            </div>
            <p class="text-muted" style="font-size:12px; margin-top:8px;">
                Оптимизации применяются к интерфейсам: opkgtun*, awg*, tun*, meta*
            </p>
        `;

        const applyEl = document.getElementById("opt-apply");
        if (applyEl) {
            applyEl.innerHTML = `
                <div class="text-muted" style="font-size:12px;">
                    Или применить к конкретному интерфейсу через API:<br>
                    <code>POST /api/optimizer/optimize {"iface":"opkgtun0","profile":"low_latency"}</code>
                </div>
            `;
        }
    }

    async function applyAll() {
        const profile = document.getElementById("opt-profile-select")?.value || "balanced";
        const btn = document.getElementById("opt-apply-btn");
        if (btn) { btn.disabled = true; btn.textContent = "Применение..."; }
        try {
            const res = await API.post("/api/optimizer/optimize-all", { profile });
            if (res.ok) {
                const applied = Object.values(res.results || {})
                    .flatMap(r => r.applied || []);
                Toast.success("Оптимизации применены: " + (applied.join(", ") || "нет активных туннелей"));
                await _loadStatus();
            } else {
                Toast.error("Ошибка: " + (res.error || "неизвестная"));
            }
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = "Применить ко всем туннелям"; }
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, applyAll };
})();
