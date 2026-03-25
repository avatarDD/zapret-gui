/**
 * logs.js — Страница логов.
 *
 * Возможности:
 *   - Real-time обновление через SSE (Server-Sent Events)
 *   - Автоматическое переподключение при обрыве
 *   - Фильтрация по уровню (DEBUG, INFO, SUCCESS, WARNING, ERROR)
 *   - Поиск по тексту
 *   - Автопрокрутка (с возможностью отключения)
 *   - Копирование всех записей в буфер обмена
 *   - Очистка буфера логов
 *   - Счётчик записей и статус подключения
 */

const LogsPage = (() => {
    // ══════════════════ State ══════════════════

    let entries = [];
    let filteredEntries = [];
    let eventSource = null;
    let reconnectTimer = null;
    let reconnectAttempts = 0;
    let autoScroll = true;
    let currentLevel = '';
    let currentSearch = '';
    let isConnected = false;
    let isPaused = false;
    let searchDebounceTimer = null;
    let statsTimer = null;
    let maxDisplayEntries = 500;

    // Цветовая карта уровней
    const LEVEL_CONFIG = {
        DEBUG:   { color: '#6b7280', bg: 'rgba(107, 114, 128, 0.1)', label: 'DEBUG',   icon: '🔍' },
        INFO:    { color: '#9ca3af', bg: 'rgba(156, 163, 175, 0.1)', label: 'INFO',    icon: 'ℹ️' },
        SUCCESS: { color: '#34d399', bg: 'rgba(52, 211, 153, 0.1)',  label: 'SUCCESS', icon: '✓' },
        WARNING: { color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.1)',  label: 'WARNING', icon: '⚠' },
        ERROR:   { color: '#f87171', bg: 'rgba(248, 113, 113, 0.1)', label: 'ERROR',   icon: '✕' },
    };

    // ══════════════════ Render ══════════════════

    function render(container) {
        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Логи</h1>
                    <p class="page-description">Журнал событий в реальном времени</p>
                </div>
                <div class="logs-header-actions">
                    <span class="logs-connection-status" id="logs-conn-status">
                        <span class="logs-conn-dot"></span>
                        <span class="logs-conn-text">Подключение...</span>
                    </span>
                </div>
            </div>

            <!-- Панель управления -->
            <div class="card logs-toolbar-card">
                <div class="logs-toolbar">
                    <div class="logs-toolbar-left">
                        <!-- Фильтр по уровню -->
                        <div class="logs-level-filters" id="logs-level-filters">
                            <button class="logs-level-btn active" data-level="" onclick="LogsPage.setLevel('')">
                                Все
                            </button>
                            <button class="logs-level-btn logs-level-error" data-level="ERROR" onclick="LogsPage.setLevel('ERROR')">
                                <span class="logs-level-dot" style="background:#f87171"></span>
                                Error
                                <span class="logs-level-count" id="count-ERROR">0</span>
                            </button>
                            <button class="logs-level-btn logs-level-warning" data-level="WARNING" onclick="LogsPage.setLevel('WARNING')">
                                <span class="logs-level-dot" style="background:#fbbf24"></span>
                                Warning
                                <span class="logs-level-count" id="count-WARNING">0</span>
                            </button>
                            <button class="logs-level-btn logs-level-success" data-level="SUCCESS" onclick="LogsPage.setLevel('SUCCESS')">
                                <span class="logs-level-dot" style="background:#34d399"></span>
                                Success
                                <span class="logs-level-count" id="count-SUCCESS">0</span>
                            </button>
                            <button class="logs-level-btn logs-level-info" data-level="INFO" onclick="LogsPage.setLevel('INFO')">
                                <span class="logs-level-dot" style="background:#9ca3af"></span>
                                Info
                                <span class="logs-level-count" id="count-INFO">0</span>
                            </button>
                            <button class="logs-level-btn logs-level-debug" data-level="DEBUG" onclick="LogsPage.setLevel('DEBUG')">
                                <span class="logs-level-dot" style="background:#6b7280"></span>
                                Debug
                                <span class="logs-level-count" id="count-DEBUG">0</span>
                            </button>
                        </div>

                        <!-- Поиск -->
                        <div class="logs-search-wrap">
                            <svg class="logs-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                            </svg>
                            <input type="text" class="form-input logs-search-input" id="logs-search"
                                   placeholder="Поиск по тексту..." oninput="LogsPage.onSearch(this.value)">
                            <button class="logs-search-clear hidden" id="logs-search-clear"
                                    onclick="LogsPage.clearSearch()" title="Очистить поиск">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="logs-toolbar-right">
                        <!-- Auto-scroll toggle -->
                        <button class="btn btn-ghost btn-sm logs-btn-autoscroll active" id="btn-autoscroll"
                                onclick="LogsPage.toggleAutoScroll()" title="Автопрокрутка">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <path d="M12 5v14M19 12l-7 7-7-7"/>
                            </svg>
                            <span class="btn-label-desktop">Авто</span>
                        </button>

                        <!-- Pause/Resume SSE -->
                        <button class="btn btn-ghost btn-sm" id="btn-pause"
                                onclick="LogsPage.togglePause()" title="Пауза/Продолжить">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" id="pause-icon">
                                <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                            </svg>
                            <span class="btn-label-desktop" id="pause-label">Пауза</span>
                        </button>

                        <!-- Copy all -->
                        <button class="btn btn-ghost btn-sm" onclick="LogsPage.copyAll()" title="Копировать все логи">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                            <span class="btn-label-desktop">Копировать</span>
                        </button>

                        <!-- Clear -->
                        <button class="btn btn-ghost btn-sm" onclick="LogsPage.clearLogs()" title="Очистить логи"
                                style="color: var(--error);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                            <span class="btn-label-desktop">Очистить</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Лог-контейнер -->
            <div class="card logs-viewer-card">
                <div class="logs-info-bar">
                    <span id="logs-entry-count">0 записей</span>
                    <span id="logs-filtered-info" class="hidden"></span>
                </div>
                <div class="logs-viewer" id="logs-viewer">
                    <div class="logs-entries" id="logs-entries">
                        <div class="logs-empty" id="logs-empty">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"
                                 width="40" height="40" style="color: var(--text-muted); margin-bottom: 12px;">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                                <line x1="16" y1="13" x2="8" y2="13"/>
                                <line x1="16" y1="17" x2="8" y2="17"/>
                                <polyline points="10 9 9 9 8 9"/>
                            </svg>
                            <div>Нет записей</div>
                            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                                Записи появятся при работе сервиса
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Индикатор паузы -->
                <div class="logs-paused-overlay hidden" id="logs-paused-overlay">
                    <span>⏸ Поток на паузе</span>
                </div>
                <!-- Кнопка "прокрутить вниз" при отключенном auto-scroll -->
                <button class="logs-scroll-bottom hidden" id="logs-scroll-bottom"
                        onclick="LogsPage.scrollToBottom()" title="Прокрутить вниз">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M12 5v14M19 12l-7 7-7-7"/>
                    </svg>
                    <span id="logs-new-count"></span>
                </button>
            </div>
        `;

        // Загружаем исторические записи, затем подключаем SSE
        loadInitialLogs();
        connectSSE();
        startStatsTimer();

        // Следим за скроллом
        const viewer = document.getElementById('logs-viewer');
        if (viewer) {
            viewer.addEventListener('scroll', onScroll);
        }
    }

    // ══════════════════ Data Loading ══════════════════

    async function loadInitialLogs() {
        try {
            const data = await API.get('/api/logs?n=500');
            if (data.ok && data.entries) {
                entries = data.entries;
                applyFilters();
                renderEntries();
                updateCounts();
                if (autoScroll) scrollToBottom();
            }
        } catch (err) {
            console.error('Failed to load logs:', err);
        }
    }

    // ══════════════════ SSE Connection ══════════════════

    function connectSSE() {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }

        try {
            eventSource = new EventSource('/api/logs/stream');

            eventSource.onopen = () => {
                isConnected = true;
                reconnectAttempts = 0;
                updateConnectionStatus('connected');
            };

            // Обработка событий типа "log"
            eventSource.addEventListener('log', (e) => {
                if (isPaused) return;

                try {
                    const entry = JSON.parse(e.data);
                    addEntry(entry);
                } catch (err) {
                    console.error('SSE parse error:', err);
                }
            });

            // Обработка дефолтных сообщений (connected, heartbeat etc.)
            eventSource.onmessage = (e) => {
                // connected event или другие
                try {
                    const data = JSON.parse(e.data);
                    if (data.type === 'connected') {
                        isConnected = true;
                        updateConnectionStatus('connected');
                    }
                } catch (err) {
                    // Ignore parse errors for heartbeats
                }
            };

            eventSource.onerror = () => {
                isConnected = false;
                updateConnectionStatus('disconnected');
                eventSource.close();
                eventSource = null;
                scheduleReconnect();
            };
        } catch (err) {
            console.error('SSE connection error:', err);
            isConnected = false;
            updateConnectionStatus('error');
            scheduleReconnect();
        }
    }

    function scheduleReconnect() {
        if (reconnectTimer) return;

        reconnectAttempts++;
        // Экспоненциальная задержка: 1s, 2s, 4s, 8s, max 30s
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);

        updateConnectionStatus('reconnecting', delay);

        reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connectSSE();
        }, delay);
    }

    function disconnectSSE() {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        isConnected = false;
    }

    // ══════════════════ Entry Management ══════════════════

    function addEntry(entry) {
        entries.push(entry);

        // Ограничиваем буфер
        if (entries.length > 2000) {
            entries = entries.slice(-1500);
        }

        // Проверяем фильтры
        if (matchesFilter(entry)) {
            filteredEntries.push(entry);

            // Ограничиваем отображаемые
            if (filteredEntries.length > maxDisplayEntries) {
                filteredEntries = filteredEntries.slice(-maxDisplayEntries);
                // Полная перерисовка при обрезке
                renderEntries();
            } else {
                // Добавляем одну строку (инкрементально)
                appendEntryDOM(entry);
            }

            if (autoScroll) {
                scrollToBottom();
            } else {
                // Показываем индикатор новых сообщений
                showNewMessageIndicator();
            }
        }

        updateCounts();
    }

    function matchesFilter(entry) {
        // Фильтр по уровню
        if (currentLevel) {
            const levelPriority = { DEBUG: 0, INFO: 1, SUCCESS: 2, WARNING: 3, ERROR: 4 };
            const minPriority = levelPriority[currentLevel] || 0;
            const entryPriority = levelPriority[entry.level] || 0;
            if (entryPriority < minPriority) return false;
        }

        // Поиск по тексту
        if (currentSearch) {
            const searchLower = currentSearch.toLowerCase();
            const text = (entry.message || '').toLowerCase() +
                         (entry.source || '').toLowerCase() +
                         (entry.level || '').toLowerCase();
            if (!text.includes(searchLower)) return false;
        }

        return true;
    }

    function applyFilters() {
        filteredEntries = entries.filter(e => matchesFilter(e));

        // Ограничиваем отображение
        if (filteredEntries.length > maxDisplayEntries) {
            filteredEntries = filteredEntries.slice(-maxDisplayEntries);
        }

        updateFilteredInfo();
    }

    // ══════════════════ DOM Rendering ══════════════════

    function renderEntries() {
        const container = document.getElementById('logs-entries');
        const emptyEl = document.getElementById('logs-empty');
        if (!container) return;

        if (filteredEntries.length === 0) {
            if (emptyEl) emptyEl.style.display = '';
            // Удаляем все строки кроме empty placeholder
            const rows = container.querySelectorAll('.log-row');
            rows.forEach(r => r.remove());
            return;
        }

        if (emptyEl) emptyEl.style.display = 'none';

        // Генерируем HTML
        const fragment = document.createDocumentFragment();

        filteredEntries.forEach(entry => {
            fragment.appendChild(createEntryElement(entry));
        });

        // Очищаем и вставляем
        const rows = container.querySelectorAll('.log-row');
        rows.forEach(r => r.remove());
        container.appendChild(fragment);

        updateFilteredInfo();
    }

    function appendEntryDOM(entry) {
        const container = document.getElementById('logs-entries');
        const emptyEl = document.getElementById('logs-empty');
        if (!container) return;

        if (emptyEl) emptyEl.style.display = 'none';

        container.appendChild(createEntryElement(entry));
    }

    function createEntryElement(entry) {
        const config = LEVEL_CONFIG[entry.level] || LEVEL_CONFIG.INFO;

        const row = document.createElement('div');
        row.className = 'log-row log-level-' + (entry.level || 'info').toLowerCase();

        const time = entry.time || '';
        const date = entry.date || '';
        const source = entry.source ? `<span class="log-source">[${escapeHtml(entry.source)}]</span>` : '';

        // Подсветка синтаксиса nfqws в сообщениях
        const rawMsg = entry.message || '';
        const nfqHighlighted = NfqwsSyntax.highlightInLog(rawMsg);
        let message;
        if (nfqHighlighted) {
            // Если есть nfqws-аргументы — используем подсветку синтаксиса
            message = highlightSearch(nfqHighlighted, true);
        } else {
            message = highlightSearch(escapeHtml(rawMsg));
        }

        row.innerHTML = `
            <span class="log-time" title="${date} ${time}">${time}</span>
            <span class="log-badge" style="color:${config.color}; background:${config.bg};">${config.label}</span>
            ${source}
            <span class="log-message">${message}</span>
        `;

        return row;
    }

    function highlightSearch(text, isHtml) {
        if (!currentSearch) return text;

        if (isHtml) {
            // Для уже HTML-подсвеченного текста — ищем только в текстовых нодах
            // Простой подход: подсвечиваем вне тегов
            const escaped = currentSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regex = new RegExp('(' + escaped + ')', 'gi');
            return text.replace(/>([^<]*)</g, (match, content) => {
                return '>' + content.replace(regex, '<mark class="log-highlight">$1</mark>') + '<';
            });
        }

        const escaped = currentSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp('(' + escaped + ')', 'gi');
        return text.replace(regex, '<mark class="log-highlight">$1</mark>');
    }

    // ══════════════════ UI Actions ══════════════════

    function setLevel(level) {
        currentLevel = level;

        // Обновляем кнопки
        document.querySelectorAll('.logs-level-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.level === level);
        });

        applyFilters();
        renderEntries();
        if (autoScroll) scrollToBottom();
    }

    function onSearch(value) {
        // Debounce 300ms
        if (searchDebounceTimer) clearTimeout(searchDebounceTimer);

        searchDebounceTimer = setTimeout(() => {
            currentSearch = value.trim();

            // Показать/скрыть кнопку очистки поиска
            const clearBtn = document.getElementById('logs-search-clear');
            if (clearBtn) {
                clearBtn.classList.toggle('hidden', !currentSearch);
            }

            applyFilters();
            renderEntries();
            if (autoScroll) scrollToBottom();
        }, 300);
    }

    function clearSearch() {
        currentSearch = '';
        const input = document.getElementById('logs-search');
        if (input) input.value = '';

        const clearBtn = document.getElementById('logs-search-clear');
        if (clearBtn) clearBtn.classList.add('hidden');

        applyFilters();
        renderEntries();
        if (autoScroll) scrollToBottom();
    }

    function toggleAutoScroll() {
        autoScroll = !autoScroll;

        const btn = document.getElementById('btn-autoscroll');
        if (btn) btn.classList.toggle('active', autoScroll);

        if (autoScroll) {
            scrollToBottom();
            hideNewMessageIndicator();
        }
    }

    function togglePause() {
        isPaused = !isPaused;

        const icon = document.getElementById('pause-icon');
        const label = document.getElementById('pause-label');
        const overlay = document.getElementById('logs-paused-overlay');

        if (isPaused) {
            if (icon) icon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"/>';
            if (label) label.textContent = 'Продолжить';
            if (overlay) overlay.classList.remove('hidden');
        } else {
            if (icon) icon.innerHTML = '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
            if (label) label.textContent = 'Пауза';
            if (overlay) overlay.classList.add('hidden');
        }
    }

    function scrollToBottom() {
        const viewer = document.getElementById('logs-viewer');
        if (viewer) {
            viewer.scrollTop = viewer.scrollHeight;
        }
        hideNewMessageIndicator();
    }

    function onScroll() {
        const viewer = document.getElementById('logs-viewer');
        if (!viewer) return;

        const atBottom = (viewer.scrollHeight - viewer.scrollTop - viewer.clientHeight) < 40;

        if (atBottom && !autoScroll) {
            // Пользователь прокрутил до конца — включаем автоскролл
            // (не включаем автоматически, чтобы не раздражать)
            hideNewMessageIndicator();
        }
    }

    let newMessageCount = 0;

    function showNewMessageIndicator() {
        newMessageCount++;
        const btn = document.getElementById('logs-scroll-bottom');
        const count = document.getElementById('logs-new-count');
        if (btn) btn.classList.remove('hidden');
        if (count) count.textContent = newMessageCount > 99 ? '99+' : newMessageCount;
    }

    function hideNewMessageIndicator() {
        newMessageCount = 0;
        const btn = document.getElementById('logs-scroll-bottom');
        if (btn) btn.classList.add('hidden');
    }

    // ══════════════════ Copy & Clear ══════════════════

    async function copyAll() {
        if (filteredEntries.length === 0) {
            Toast.show('Нет записей для копирования', 'warning');
            return;
        }

        const text = filteredEntries.map(e => {
            const src = e.source ? ` [${e.source}]` : '';
            return `${e.date || ''} ${e.time || ''} [${e.level}]${src} ${e.message}`;
        }).join('\n');

        try {
            await navigator.clipboard.writeText(text);
            Toast.show(`Скопировано ${filteredEntries.length} записей`, 'success');
        } catch (err) {
            // Fallback: textarea
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                Toast.show(`Скопировано ${filteredEntries.length} записей`, 'success');
            } catch (e2) {
                Toast.show('Не удалось скопировать', 'error');
            }
            document.body.removeChild(ta);
        }
    }

    async function clearLogs() {
        if (!confirm('Очистить все записи логов?')) return;

        try {
            await API.post('/api/logs/clear');
            entries = [];
            filteredEntries = [];
            renderEntries();
            updateCounts();
            Toast.show('Логи очищены', 'success');
        } catch (err) {
            Toast.show('Ошибка: ' + err.message, 'error');
        }
    }

    // ══════════════════ Status & Counts ══════════════════

    function updateConnectionStatus(status, delay) {
        const el = document.getElementById('logs-conn-status');
        if (!el) return;

        const dot = el.querySelector('.logs-conn-dot');
        const text = el.querySelector('.logs-conn-text');

        el.className = 'logs-connection-status logs-conn-' + status;

        switch (status) {
            case 'connected':
                if (text) text.textContent = 'Подключено';
                break;
            case 'disconnected':
                if (text) text.textContent = 'Отключено';
                break;
            case 'reconnecting':
                if (text) text.textContent = 'Переподключение... (' + Math.round(delay / 1000) + 'с)';
                break;
            case 'error':
                if (text) text.textContent = 'Ошибка соединения';
                break;
        }
    }

    function updateCounts() {
        // Обновляем счётчики по уровням
        const counts = { DEBUG: 0, INFO: 0, SUCCESS: 0, WARNING: 0, ERROR: 0 };
        entries.forEach(e => {
            if (counts.hasOwnProperty(e.level)) {
                counts[e.level]++;
            }
        });

        Object.keys(counts).forEach(level => {
            const el = document.getElementById('count-' + level);
            if (el) el.textContent = counts[level];
        });

        // Общий счётчик
        const countEl = document.getElementById('logs-entry-count');
        if (countEl) {
            countEl.textContent = entries.length + ' ' + pluralize(entries.length, 'запись', 'записи', 'записей');
        }
    }

    function updateFilteredInfo() {
        const el = document.getElementById('logs-filtered-info');
        if (!el) return;

        if (currentLevel || currentSearch) {
            el.classList.remove('hidden');
            el.textContent = '(показано: ' + filteredEntries.length + ')';
        } else {
            el.classList.add('hidden');
        }
    }

    function startStatsTimer() {
        // Обновляем счётчики периодически (на случай если SSE пропустил)
        statsTimer = setInterval(() => {
            updateCounts();
        }, 10000);
    }

    // ══════════════════ Utils ══════════════════

    function pluralize(n, one, few, many) {
        const abs = Math.abs(n) % 100;
        const lastDigit = abs % 10;
        if (abs > 10 && abs < 20) return many;
        if (lastDigit > 1 && lastDigit < 5) return few;
        if (lastDigit === 1) return one;
        return many;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ══════════════════ Destroy ══════════════════

    function destroy() {
        disconnectSSE();

        if (searchDebounceTimer) {
            clearTimeout(searchDebounceTimer);
            searchDebounceTimer = null;
        }

        if (statsTimer) {
            clearInterval(statsTimer);
            statsTimer = null;
        }

        entries = [];
        filteredEntries = [];
        newMessageCount = 0;
    }

    // ══════════════════ Public API ══════════════════

    return {
        render,
        destroy,
        setLevel,
        onSearch,
        clearSearch,
        toggleAutoScroll,
        togglePause,
        scrollToBottom,
        copyAll,
        clearLogs,
    };
})();


