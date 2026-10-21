# core/registrable.py
"""
Регистрируемый домен по Public Suffix List: ``api.example.co.uk`` →
``example.co.uk``, ``user.github.io`` → ``user.github.io``.

Автообнаружение (``core/smart_detect``) добавляет в список не точное имя
хоста, а домен, который можно зарегистрировать: заблокированный сервис
приходит десятком поддоменов (``cdn1``, ``api``, ``static``), и
список из точных имён догонял бы их неделями. Наивное «две последние
метки» ломается на ``co.uk``, ``com.ru`` и хостингах вроде
``github.io``, где каждый поддомен — чужой сайт. Отсюда PSL.

Снимок списка — ``data/public_suffix_list.dat`` (MPL-2.0, без
комментариев, IDN в punycode). Читается один раз, лениво.
"""

from __future__ import annotations

import os
import threading

_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "data", "public_suffix_list.dat")

_lock = threading.Lock()
_rules = None        # (exact: set, wildcard: set, exception: set)


def parse_rules(lines) -> tuple:
    """Чистая функция: строки PSL → (обычные, ``*.``-правила, ``!``-исключения)."""
    exact, wild, exc = set(), set(), set()
    for ln in lines:
        ln = ln.strip().lower()
        if not ln or ln.startswith("//"):
            continue
        if ln.startswith("!"):
            exc.add(ln[1:])
        elif ln.startswith("*."):
            wild.add(ln[2:])
        else:
            exact.add(ln)
    return exact, wild, exc


def _load() -> tuple:
    global _rules
    with _lock:
        if _rules is None:
            try:
                with open(_PATH, encoding="utf-8") as f:
                    _rules = parse_rules(f)
            except (OSError, UnicodeDecodeError):
                _rules = (set(), set(), set())
        return _rules


def registrable(domain: str, rules: tuple = None) -> str:
    """Регистрируемый домен или ``""`` (сам домен — публичный суффикс).

    Алгоритм PSL: самое длинное подходящее правило; исключение (``!``)
    важнее подстановки; без подходящего правила суффикс — последняя
    метка (правило ``*``).
    """
    d = (domain or "").strip().strip(".").lower()
    if not d:
        return ""
    labels = d.split(".")
    exact, wild, exc = rules or _load()
    suffix_len = 1
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        n = len(labels) - i
        if cand in exc:
            suffix_len = n - 1
            break
        if cand in exact and n > suffix_len:
            suffix_len = n
        parent = ".".join(labels[i + 1:])
        if parent and parent in wild and n > suffix_len:
            suffix_len = n
    if len(labels) <= suffix_len:
        return ""
    return ".".join(labels[-(suffix_len + 1):])
