#!/usr/bin/env python3
"""
bundle.py — Минимизация и конкатенация CSS/JS для zapret-gui.

MR-119: Уменьшает размер бандла для production путём:
  - конкатенации CSS/JS файлов в один бандл
  - базовой минификации (удаление комментариев, лишних пробелов)

Использование:
  python tools/bundle.py           # собрать бандлы в web/dist/
  python tools/bundle.py --dev     # только конкатенация без минификации

Требования: Python 3.8+
"""

import argparse
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
DIST_DIR = os.path.join(WEB_DIR, "dist")

# Добавляем PROJECT_ROOT в sys.path для импорта core.version
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# CSS файлы в порядке загрузки (основной стиль первым, дополнения после)
CSS_FILES = [
    "css/style.css",
    "css/blockcheck_scan.css",
]

# JS файлы в порядке загрузки — соответствует порядку в index.html
JS_FILES = [
    # i18n
    "js/i18n/ru.js",
    "js/i18n/en.js",
    "js/utils/i18n.js",
    # API
    "js/api.js",
    # utils
    "js/utils/theme-init.js",
    "js/utils/debounce.js",
    "js/utils/nfqws2_spec.js",
    "js/utils/nfqws2_lint.js",
    "js/utils/syntax.js",
    "js/utils/lua_syntax.js",
    "js/utils/autocomplete.js",
    # components
    "js/components/toast.js",
    "js/components/theme.js",
    "js/components/expert.js",
    "js/components/sidebar.js",
    "js/components/list_ui.js",
    "js/components/sparkline.js",
    "js/components/help.js",
    "js/components/transport_select.js",
    "js/components/confirm.js",
    "js/components/setup_ui.js",
    "js/components/proxy_table.js",
    # pages
    "js/pages/dashboard.js",
    "js/pages/control.js",
    "js/pages/strategies.js",
    "js/pages/hostlists.js",
    "js/pages/ipsets.js",
    "js/pages/lua_scripts.js",
    "js/pages/blobs.js",
    "js/pages/hosts.js",
    "js/pages/diagnostics.js",
    "js/pages/blockcheck.js",
    "js/pages/blockcheck2.js",
    "js/pages/scan.js",
    "js/pages/logs.js",
    "js/pages/autostart.js",
    "js/pages/zapret_manager.js",
    "js/pages/awg_setup.js",
    "js/pages/awg_dashboard.js",
    "js/pages/awg_configs.js",
    "js/pages/awg_warp.js",
    "js/pages/awg_routing.js",
    "js/pages/singbox.js",
    "js/pages/singbox_configs.js",
    "js/pages/singbox_proxies.js",
    "js/pages/singbox_setup.js",
    "js/pages/mihomo.js",
    "js/pages/mihomo_proxies.js",
    "js/pages/mihomo_setup.js",
    "js/pages/usque.js",
    "js/pages/usque_setup.js",
    "js/pages/warp_in_warp.js",
    "js/pages/tunnel_monitor.js",
    "js/pages/tunnel_optimizer.js",
    "js/pages/dns_routing.js",
    "js/pages/tgproxy.js",
    "js/pages/block_detector.js",
    "js/pages/opera_proxy.js",
    "js/pages/update_checker.js",
    "js/pages/lists.js",
    "js/pages/routing_unified.js",
    "js/pages/settings.js",
    # app.js всегда последним
    "js/app.js",
]


def minify_css(text: str) -> str:
    """Базовая минификация CSS (удаление комментариев, лишних пробелов)."""
    # Удаляем многострочные комментарии
    text = re.sub(r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/", "", text)
    # Удаляем лишние пробелы
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([{};,:])\s*", r"\1", text)
    text = re.sub(r";}", "}", text)
    return text


def minify_js(text: str) -> str:
    """MR-119: Улучшенная минификация JS."""
    # Удаляем однострочные комментарии (осторожно: не внутри строк)
    lines = text.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        # Удаляем inline // комментарии вне строк
        if "//" in line:
            parts = line.split('"')
            clean_parts = []
            for i, part in enumerate(parts):
                if i % 2 == 0 and "//" in part:
                    clean_parts.append(part.split("//")[0])
                else:
                    clean_parts.append(part)
            line = '"'.join(clean_parts)
        result.append(line)
    text = "\n".join(result)
    text = re.sub(r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/", "", text)
    # Удаляем пустые строки
    text = re.sub(r"\n\s*\n", "\n", text)
    # Удаляем ведущие/замыкающие пробелы строк
    text = "\n".join(line.strip() for line in text.split("\n"))
    # Удаляем лишние пробелы (сохраняя строковые литералы)
    text = re.sub(r"(?<!['\"])\s{2,}(?!['\"])", " ", text)
    # Удаляем пробелы вокруг операторов (кроме строк)
    text = re.sub(r"\s*([=+\-*/{}();,:])\s*", r"\1", text)
    # Восстанавливаем пробелы после ключевых слов
    for kw in ("return", "var", "const", "let", "if", "else", "for", "while",
               "function", "class", "new", "typeof", "instanceof", "in", "of"):
        text = re.sub(rf"\b{kw}(\S)", rf"{kw} \1", text)
    return text


def read_file(path: str) -> str:
    """Чтение файла с обработкой ошибок."""
    full_path = os.path.join(WEB_DIR, path) if not os.path.isabs(path) else path
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"  ! Предупреждение: файл не найден: {full_path}", file=sys.stderr)
        return ""
    except Exception as e:
        print(f"  ! Ошибка чтения {full_path}: {e}", file=sys.stderr)
        return ""


def write_bundle(path: str, content: str):
    """Запись бандла."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    size_kb = len(content.encode("utf-8")) / 1024
    print(f"  OK {os.path.relpath(path, PROJECT_ROOT)} ({size_kb:.1f} KB)")


def build(dev_mode: bool = False):
    """Сборка бандлов."""
    print(f"{'='*60}")
    print("  Zapret GUI Bundle Builder")
    print(f"  Mode: {'DEV (concat only)' if dev_mode else 'PRODUCTION (minified)'}")
    print(f"{'='*60}")

    # ── CSS бандл ──
    print("\n--- CSS:")
    css_parts = []
    for f in CSS_FILES:
        content = read_file(f)
        if content:
            if not dev_mode:
                content = minify_css(content)
            css_parts.append(f"/* {f} */\n{content}")
        else:
            print(f"  SKIP: {f}")

    css_bundle = "\n".join(css_parts)
    write_bundle(os.path.join(DIST_DIR, "bundle.css"), css_bundle)

    # ── JS бандл ──
    print("\n--- JS:")
    js_parts = []

    for f in JS_FILES:
        content = read_file(f)
        if content:
            if not dev_mode:
                content = minify_js(content)
            js_parts.append(f"/* {f} */\n{content}")
        else:
            print(f"  SKIP: {f}")

    # Вставляем заголовок
    from datetime import datetime
    from core.version import GUI_VERSION
    header = f"// Zapret GUI v{GUI_VERSION} — bundled {datetime.now().strftime('%Y-%m-%d')}\n"
    js_bundle = header + "\n".join(js_parts)
    write_bundle(os.path.join(DIST_DIR, "bundle.js"), js_bundle)

    # ── Итого ──
    print(f"\n{'='*60}")
    css_path = os.path.join(DIST_DIR, "bundle.css")
    js_path = os.path.join(DIST_DIR, "bundle.js")
    total_size = (os.path.getsize(css_path) + os.path.getsize(js_path)) / 1024

    # Сравнение с оригиналом
    original_size = sum(
        os.path.getsize(os.path.join(WEB_DIR, f)) for f in CSS_FILES + JS_FILES
        if os.path.exists(os.path.join(WEB_DIR, f))
    ) / 1024

    print(f"  Original:        ~{original_size:.0f} KB")
    print(f"  Bundle:          {total_size:.0f} KB")
    print(f"  Savings:         ~{original_size - total_size:.0f} KB ({(1 - total_size/original_size)*100:.0f}%)")
    print(f"{'='*60}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zapret GUI Bundle Builder")
    parser.add_argument("--dev", action="store_true", help="Dev mode: concat only, no minification")
    args = parser.parse_args()

    success = build(dev_mode=args.dev)
    sys.exit(0 if success else 1)
