/**
 * usque_setup.js — Страница установки/обновления usque-keenetic.
 */

const UsqueSetupPage = (() => {
    async function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <h1>Установка usque-keenetic</h1>
                <span class="page-subtitle">Cloudflare WARP через MASQUE-протокол</span>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Информация</div>
                    <div class="card-body">
                        <p><strong>usque-keenetic</strong> — адаптация <a href="https://github.com/Diniboy1123/usque" target="_blank">usque</a> для Keenetic роутеров.</p>
                        <p>Использует MASQUE-протокол (port 443) для обхода DPI. Трафик маскируется под обычный HTTPS.</p>
                        <ul>
                            <li>Протокол: MASQUE (не WireGuard)</li>
                            <li>Порт: 443 (маскировка под HTTPS)</li>
                            <li>SNI-маскировка: настраивается</li>
                            <li>Реализация: Go (userspace TUN)</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Установка через opkg</div>
                    <div class="card-body">
                        <p>Если доступен репозиторий usque-keenetic:</p>
                        <pre><code>opkg update && opkg install usque-keenetic</code></pre>
                        <p class="text-muted">Или добавьте репозиторий вручную:</p>
                        <pre><code>echo "src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all" > /opt/etc/opkg/usque-keenetic.conf
opkg update && opkg install usque-keenetic</code></pre>
                    </div>
                </div>
            </div>

            <div class="card-grid">
                <div class="card">
                    <div class="card-title">Ручная установка</div>
                    <div class="card-body">
                        <p>Скачайте бинарник для вашей архитектуры:</p>
                        <pre><code># ARM64 (Hero, Ultra, Giga, Hopper)
curl -Lo /opt/usr/bin/usque https://github.com/side-effect-tm/usque-keenetic/releases/latest/download/usque-aarch64
chmod +x /opt/usr/bin/usque

# MIPSel (Extra, Start, Air)
curl -Lo /opt/usr/bin/usque https://github.com/side-effect-tm/usque-keenetic/releases/latest/download/usque-mipsel
chmod +x /opt/usr/bin/usque</code></pre>
                    </div>
                </div>
            </div>
        `;
    }

    function destroy() {}

    return { render, destroy };
})();
