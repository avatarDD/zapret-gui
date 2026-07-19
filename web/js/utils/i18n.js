const i18n = (() => {
    let currentLang = localStorage.getItem('zapret-gui-lang') || 'ru';

    function getTranslations() {
        if (currentLang === 'en') {
            return typeof i18n_en !== 'undefined' ? i18n_en : {};
        }
        return typeof i18n_ru !== 'undefined' ? i18n_ru : {};
    }

    function translate(key, variables = {}) {
        const translations = getTranslations();
        let text = translations[key] || key;

        for (const [varName, varVal] of Object.entries(variables)) {
            text = text.replace(new RegExp(`{${varName}}`, 'g'), varVal);
        }
        return text;
    }

    function getLanguage() {
        return currentLang;
    }

    function setLanguage(lang) {
        if (lang === 'ru' || lang === 'en') {
            localStorage.setItem('zapret-gui-lang', lang);
            currentLang = lang;
            location.reload();
        }
    }

    return {
        t: translate,
        getLanguage,
        setLanguage
    };
})();

// Глобальная функция для удобства
const _t = i18n.t;

document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('lang-toggle');
    if (btn) {
        btn.textContent = i18n.getLanguage().toUpperCase();
    }
});
