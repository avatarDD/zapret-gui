/**
 * sparkline.js — крошечный inline-SVG спарклайн (без зависимостей).
 *
 * Sparkline.svg(values, opts) → строка <svg> с polyline по значениям.
 * Используется для per-iface / per-peer rx/tx серий
 * (backend: /api/connectivity/traffic/<iface>).
 */

const Sparkline = (() => {

    function svg(values, opts) {
        opts = opts || {};
        const w = opts.width || 90;
        const h = opts.height || 22;
        const stroke = opts.stroke || '#39c45e';
        const fill = opts.fill || 'rgba(57,196,94,0.12)';
        const vals = (values || []).map(v => Number(v) || 0);
        if (vals.length < 2) {
            return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"
                style="vertical-align:middle;"></svg>`;
        }
        const max = Math.max.apply(null, vals);
        const min = Math.min.apply(null, vals);
        const range = (max - min) || 1;
        const n = vals.length;
        const dx = w / (n - 1);
        const pad = 2;
        const ih = h - pad * 2;
        const pts = vals.map((v, i) => {
            const x = i * dx;
            const y = pad + ih - ((v - min) / range) * ih;
            return x.toFixed(1) + ',' + y.toFixed(1);
        });
        const line = pts.join(' ');
        const area = `0,${h} ${line} ${w},${h}`;
        return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"
            preserveAspectRatio="none" style="vertical-align:middle;">
            <polyline points="${area}" fill="${fill}" stroke="none"/>
            <polyline points="${line}" fill="none" stroke="${stroke}"
                      stroke-width="1.5" stroke-linejoin="round"/>
        </svg>`;
    }

    /** Человекочитаемый bps: 12.3 Kbit/s и т.п. */
    function fmtBps(bps) {
        bps = Number(bps) || 0;
        const bits = bps * 8;
        if (bits < 1000) return bits.toFixed(0) + ' bit/s';
        if (bits < 1e6) return (bits / 1e3).toFixed(1) + ' Kbit/s';
        if (bits < 1e9) return (bits / 1e6).toFixed(1) + ' Mbit/s';
        return (bits / 1e9).toFixed(2) + ' Gbit/s';
    }

    /**
     * Готовый блок «rx/tx спарклайны» из series [{ts,rx_bps,tx_bps}].
     */
    function trafficBlock(series) {
        series = series || [];
        const rx = series.map(s => s.rx_bps);
        const tx = series.map(s => s.tx_bps);
        const lastRx = rx.length ? rx[rx.length - 1] : 0;
        const lastTx = tx.length ? tx[tx.length - 1] : 0;
        return `
            <span style="display:inline-flex; gap:12px; align-items:center; font-size:11px;">
                <span title="входящий трафик" style="display:inline-flex; gap:4px; align-items:center;">
                    <span style="color:#39c45e;">▼</span>
                    ${svg(rx, { stroke: '#39c45e', fill: 'rgba(57,196,94,0.12)' })}
                    <span class="text-muted">${fmtBps(lastRx)}</span>
                </span>
                <span title="исходящий трафик" style="display:inline-flex; gap:4px; align-items:center;">
                    <span style="color:#4aa3ff;">▲</span>
                    ${svg(tx, { stroke: '#4aa3ff', fill: 'rgba(74,163,255,0.12)' })}
                    <span class="text-muted">${fmtBps(lastTx)}</span>
                </span>
            </span>`;
    }

    return { svg, fmtBps, trafficBlock };
})();
