/**
 * confirm.js — Стилизованная модальное окно подтверждения (MR-120).
 *
 * Заменяет нативный confirm() на styled modal с Promise-based API.
 * Использование:
 *   const ok = await Confirm.show("Заголовок", "Сообщение", { danger: true });
 *   if (!ok) return;
 */

const Confirm = (() => {

    /**
     * Показать модальное окно подтверждения.
     * @param {string} title - Заголовок
     * @param {string} message - HTML-сообщение
     * @param {object} opts - Настройки
     * @param {string} opts.confirmLabel - Текст кнопки подтверждения (по умолчанию "OK")
     * @param {boolean} opts.danger - Красная кнопка подтверждения
     * @returns {Promise<boolean>} true если подтверждено, false если отменено
     */
    function show(title, message, opts = {}) {
        return new Promise((resolve) => {
            const old = document.getElementById("confirm-modal-overlay");
            if (old) old.remove();

            const confirmLabel = opts.confirmLabel || "OK";
            const dangerClass = opts.danger ? "btn-danger" : "";
            const dangerStyle = opts.danger
                ? "background:#e58; color:#fff; border-color:#e58;"
                : "";

            const overlay = document.createElement("div");
            overlay.id = "confirm-modal-overlay";
            overlay.className = "modal-overlay";
            overlay.style.position = "fixed";
            overlay.style.inset = "0";
            overlay.style.backgroundColor = "rgba(0, 0, 0, 0.5)";
            overlay.style.display = "flex";
            overlay.style.alignItems = "center";
            overlay.style.justifyContent = "center";
            overlay.style.zIndex = "1000";

            const content = document.createElement("div");
            content.className = "modal-content";
            content.style.backgroundColor = "var(--bg-card, #1a1d28)";
            content.style.padding = "24px";
            content.style.borderRadius = "8px";
            content.style.width = "90%";
            content.style.maxWidth = "400px";
            content.style.boxShadow = "0 4px 12px rgba(0,0,0,0.3)";

            content.innerHTML = `
                <div style="font-weight:bold; font-size:1.1rem; margin-bottom:12px; color:var(--text-main, #e1e4ea);">${title}</div>
                <div style="margin-bottom:20px; font-size:0.95rem; line-height:1.4; color:var(--text-secondary, #a0a6b5);">${message}</div>
                <div style="display:flex; justify-content:flex-end; gap:8px;">
                    <button class="btn" id="confirm-modal-cancel">Отмена</button>
                    <button class="btn ${dangerClass}" id="confirm-modal-ok" style="${dangerStyle} cursor:pointer;">${confirmLabel}</button>
                </div>
            `;

            overlay.appendChild(content);
            document.body.appendChild(overlay);

            const okBtn = document.getElementById("confirm-modal-ok");
            const cancelBtn = document.getElementById("confirm-modal-cancel");

            function cleanUp(result) {
                overlay.remove();
                resolve(result);
            }

            okBtn.addEventListener("click", () => cleanUp(true));
            cancelBtn.addEventListener("click", () => cleanUp(false));
            overlay.addEventListener("click", (e) => {
                if (e.target === overlay) cleanUp(false);
            });
            document.addEventListener("keydown", function onKey(e) {
                if (e.key === "Escape") {
                    document.removeEventListener("keydown", onKey);
                    cleanUp(false);
                }
            });
        });
    }

    return { show };
})();
