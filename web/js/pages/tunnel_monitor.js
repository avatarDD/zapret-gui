/**
 * tunnel_monitor.js — Live мониторинг туннелей.
 *
 * Графики трафика (rx/tx), latency, throughput для всех туннельных интерфейсов.
 */

const TunnelMonitorPage = (() => {
    let _pollTimer = null;
    const POLL_MS = 5000;

    let _visibilityHandler = null;
    let _inFlight = false;

    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Мониторинг туннелей</h1>
                <span class="page-subtitle">Live графики трафика, latency, throughput</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Статус</div>
                    <div class="card-body" id="tm-status">Загрузка...</div>
                </div>
            </div>

            <div id="tm-charts"></div>
        `;

        _visibilityHandler = () => {
            if (document.hidden) _stopPoll();
            else _startPoll();
        };
        document.addEventListener("visibilitychange", _visibilityHandler);

        await _refresh();
        _startPoll();
    }

    function destroy() {
        _stopPoll();
        if (_visibilityHandler) {
            document.removeEventListener("visibilitychange", _visibilityHandler);
            _visibilityHandler = null;
        }
    }

    async function _refresh() {
        if (_inFlight || document.hidden) return;
        _inFlight = true;
        try {
            const data = await API.get("/api/monitor/metrics");
            _renderCharts(data.metrics || []);
        } catch (e) {
            const el = document.getElementById("tm-charts");
            if (el) el.innerHTML = `<div class="text-error">Ошибка: ${esc(String(e))}</div>`;
        } finally {
            _inFlight = false;
        }
    }

    function _renderCharts(metrics) {
        const el = document.getElementById("tm-charts");
        if (!el) return;

        if (!metrics.length) {
            el.innerHTML = `
                <div class="card">
                    <div class="card-body text-muted" style="text-align:center; padding:32px;">
                        Нет активных туннелей. Запустите WARP, AWG, sing-box или другой туннель.
                    </div>
                </div>`;
            return;
        }

        const IFACE_NAMES = {
            "__nfqws2__": "nfqws2 (DPI bypass)",
            "__opera_proxy__": "Opera Proxy (HTTP/SOCKS5)",
            "__tgproxy__": "Telegram MTProto Proxy",
        };

        let html = '';
        for (const m of metrics) {
            const displayName = IFACE_NAMES[m.iface] || m.iface;
            const rxSpeed = _formatSpeed(m.rx_speed);
            const txSpeed = _formatSpeed(m.tx_speed);
            const rxAvg = _formatSpeed(m.rx_avg_1m);
            const txAvg = _formatSpeed(m.tx_avg_1m);
            const rxTotal = _formatBytes(m.rx_bytes);
            const txTotal = _formatBytes(m.tx_bytes);

            // Мини-график rx/tx
            const chart = m.chart || [];
            const chartSvg = _renderMiniChart(chart);

            html += `
                <div class="card" style="margin-bottom:12px;">
                    <div class="card-title" style="display:flex; justify-content:space-between;">
                        <span><code>${esc(displayName)}</code></span>
                        <span style="font-size:12px; font-weight:normal;">
                            ↓ ${rxSpeed} · ↑ ${txSpeed}
                        </span>
                    </div>
                    <div class="card-body">
                        <div style="display:flex; gap:24px; flex-wrap:wrap;">
                            <div>
                                <div class="text-muted" style="font-size:11px;">RX (получено)</div>
                                <div style="font-size:18px; font-weight:600;">${rxTotal}</div>
                                <div class="text-muted" style="font-size:11px;">сейчас: ${rxSpeed} · средняя: ${rxAvg}</div>
                            </div>
                            <div>
                                <div class="text-muted" style="font-size:11px;">TX (отправлено)</div>
                                <div style="font-size:18px; font-weight:600;">${txTotal}</div>
                                <div class="text-muted" style="font-size:11px;">сейчас: ${txSpeed} · средняя: ${txAvg}</div>
                            </div>
                            <div style="flex:1; min-width:200px;">
                                <div class="text-muted" style="font-size:11px;">Трафик (5мин)</div>
                                ${chartSvg}
                            </div>
                        </div>
                    </div>
                </div>`;
        }

        el.innerHTML = html;
    }

    function _renderMiniChart(chart) {
        if (!chart || chart.length < 2) {
            return '<div class="text-muted" style="font-size:11px;">Нет данных</div>';
        }

        const width = 200;
        const height = 40;
        const padding = 2;

        // Берём последние 60 точек
        const points = chart.slice(-60);
        if (points.length < 2) {
            return '<div class="text-muted" style="font-size:11px;">Нет данных</div>';
        }

        // Вычисляем скорости
        const speeds = [];
        for (let i = 1; i < points.length; i++) {
            const dt = points[i][0] - points[i-1][0];
            const drx = points[i][1] - points[i-1][1];
            const dtx = points[i][2] - points[i-1][2];
            speeds.push({
                rx: dt > 0 ? drx / dt : 0,
                tx: dt > 0 ? dtx / dt : 0,
            });
        }

        const maxSpeed = Math.max(1, ...speeds.map(s => Math.max(s.rx, s.tx)));

        // Строим polyline для rx и tx
        const rxPoints = speeds.map((s, i) => {
            const x = padding + (i / (speeds.length - 1)) * (width - 2 * padding);
            const y = height - padding - (s.rx / maxSpeed) * (height - 2 * padding);
            return `${x},${y}`;
        }).join(' ');

        const txPoints = speeds.map((s, i) => {
            const x = padding + (i / (speeds.length - 1)) * (width - 2 * padding);
            const y = height - padding - (s.tx / maxSpeed) * (height - 2 * padding);
            return `${x},${y}`;
        }).join(' ');

        return `
            <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" width="100%" height="${height}" style="display:block;">
                <polyline points="${rxPoints}" fill="none" stroke="#22c55e" stroke-width="1.5" opacity="0.8"/>
                <polyline points="${txPoints}" fill="none" stroke="#f97316" stroke-width="1.5" opacity="0.8"/>
            </svg>
            <div style="font-size:10px; margin-top:2px;">
                <span style="color:#22c55e;">● RX</span>
                <span style="color:#f97316; margin-left:8px;">● TX</span>
            </div>`;
    }

    function _formatSpeed(bytesPerSec) {
        if (bytesPerSec < 1024) return Math.round(bytesPerSec) + ' B/s';
        if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
        return (bytesPerSec / (1024 * 1024)).toFixed(1) + ' MB/s';
    }

    function _formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    function _startPoll() {
        if (!_pollTimer) {
            _pollTimer = setInterval(_refresh, POLL_MS);
        }
    }

    function _stopPoll() {
        if (_pollTimer) {
            clearInterval(_pollTimer);
            _pollTimer = null;
        }
    }

    function esc(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    return { render, destroy };
})();
