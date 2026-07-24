// theme-init.js — Применяем тему ДО отрисовки (без внешнего CSS),
// чтобы не было «вспышки» тёмного. Загрузка синхронная, блокирующая
// (без defer/async) — единственная цель этого файла.
// MR-123: вынесен из inline <script> для поддержки CSP.
(function () {
  try {
    const t = localStorage.getItem('zapret-gui-theme');
    document.documentElement.setAttribute(
      'data-theme', (t === 'light' || t === 'dark') ? t : 'dark');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
