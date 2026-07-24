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
                <h1>Оптимизации туннелей${typeof Help !== 'undefined' ? Help.button('tunnel-optimizer') : ''}</h1>
                <span class="page-subtitle">MTU/PMTU, безопасные TCP/QUIC buffers, BBR и полный restore</span>
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
                                <tr><td>QUIC/UDP ceiling</td><td colspan="3">до 8 MB для WARP/QUIC, только повышение</td></tr>
                                <tr><td>BBR</td><td colspan="3">Только TCP-соединения, создаваемые/завершаемые роутером</td></tr>
                                <tr><td>TCP Fast Open</td><td colspan="3">не меняется: требуется поддержка приложения</td></tr>
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
                html += `<tr>
                    <td>${label}</td>
                    <td><code>${esc(val)}</code></td>
                    <td>${_statusMark(key, _status)}</td>
                </tr>`;
            }
            html += '</tbody></table>';
            el.innerHTML = html;
        } catch (e) {
            const el = document.getElementById("opt-status");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        }
    }

    // Индикатор состояния строки. Для congestion control учитываем, что
    // BBR может быть НЕдоступен в ядре роутера — тогда cubic это норма, а
    // не проблема (⚠️ вводило в заблуждение). Остальные строки —
    // информационные (оптимизатор их намеренно не форсит), поэтому нейтральны.
    function _statusMark(key, status) {
        const OK = '<span style="color:var(--success);" title="активно">✅</span>';
        const NEUTRAL = '<span class="text-muted" title="информационно">—</span>';
        if (key === "tcp_congestion_control") {
            const val = String(status[key] || "");
            if (val.includes("bbr")) return OK;
            const avail = String(status.available_cc || "");
            if (avail.includes("bbr")) {
                return '<span style="color:var(--warning);" title="BBR доступен — примените профиль оптимизации, чтобы включить его">⚠️</span>';
            }
            return '<span class="text-muted" title="BBR недоступен в этом ядре; cubic — нормальный дефолт, менять не требуется">ℹ️</span>';
        }
        return NEUTRAL;
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
                <button class="btn btn-danger" id="opt-restore-btn"
                        onclick="TunnelOptimizerPage.restoreAll()">Полностью восстановить</button>
            </div>
            <p class="text-muted" style="font-size:12px; margin-top:8px;">
                Оптимизации применяются к интерфейсам: opkgtun*, awg*, tun*, meta*
            </p>
        `;

        const applyEl = document.getElementById("opt-apply");
        if (applyEl) {
            applyEl.innerHTML = `
                <div class="form-grid">
                    <div class="form-group">
                        <label>Интерфейс для PMTU-проверки</label>
                        <input id="opt-pmtu-iface" class="form-control" placeholder="opkgtun0">
                    </div>
                    <div class="form-group">
                        <label>IP назначения</label>
                        <input id="opt-pmtu-host" class="form-control" value="1.1.1.1">
                    </div>
                </div>
                <button class="btn" style="margin-top:8px;" onclick="TunnelOptimizerPage.probePmtu()">
                    Проверить dataplane PMTU
                </button>
                <div id="opt-pmtu-result" class="text-muted" style="font-size:12px; margin-top:8px;"></div>
                <div class="text-muted" style="font-size:12px; margin-top:12px;">
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

    async function restoreAll() {
        if (!confirm("Восстановить сохранённые sysctl, MTU, qdisc и удалить MSS-правила optimizer?")) return;
        const btn = document.getElementById("opt-restore-btn");
        if (btn) btn.disabled = true;
        try {
            const res = await API.post("/api/optimizer/restore");
            if (res.ok) Toast.success("Сетевые настройки восстановлены");
            else Toast.error((res.errors || [res.error || "Ошибка восстановления"]).join("; "));
            await _loadStatus();
        } catch (e) {
            Toast.error("Ошибка: " + e.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function probePmtu() {
        const iface = document.getElementById("opt-pmtu-iface")?.value.trim() || "";
        const host = document.getElementById("opt-pmtu-host")?.value.trim() || "1.1.1.1";
        const el = document.getElementById("opt-pmtu-result");
        if (!iface) { Toast.error("Укажите интерфейс"); return; }
        if (el) el.textContent = "Проверка...";
        try {
            // PMTU — бинарный поиск пингами (до ~30с на iputils): свой таймаут.
            const res = await API.post("/api/optimizer/probe-pmtu", { iface, host }, { timeout: 60000 });
            if (res.ok) {
                if (el) el.textContent = `PMTU: ${res.pmtu}; IPv6 minimum: ${res.ipv6_safe ? "OK" : "нет"}`;
            } else {
                if (el) el.textContent = res.error || "PMTU определить не удалось";
            }
        } catch (e) {
            if (el) el.textContent = "Ошибка: " + e.message;
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy, applyAll, restoreAll, probePmtu };
})();
