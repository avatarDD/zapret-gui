# core/testers/__init__.py
"""
Пакет продвинутых сетевых тестеров для blockcheck.

Дополняет существующий core/diagnostics.py (ping, HTTP curl/wget, DNS)
низкоуровневыми проверками через stdlib (socket + ssl).

Использование:
    from core.testers.tls_tester import test_tls
    from core.testers.stun_tester import test_stun
    from core.testers.tcp_test import check_tcp_16_20
    from core.testers.isp_detector import detect_isp_page, check_http_injection
    from core.testers.dpi_classifier import DPIClassifier
"""

__all__ = [
    "test_tls",
    "test_stun",
    "check_tcp_16_20",
    "detect_isp_page",
    "check_http_injection",
    "DPIClassifier",
]


def test_tls(host, **kwargs):
    """Ленивый импорт — экономия памяти на роутере."""
    from core.testers.tls_tester import test_tls as _fn
    return _fn(host, **kwargs)


def test_stun(host, **kwargs):
    from core.testers.stun_tester import test_stun as _fn
    return _fn(host, **kwargs)


def check_tcp_16_20(url, **kwargs):
    from core.testers.tcp_test import check_tcp_16_20 as _fn
    return _fn(url, **kwargs)


def detect_isp_page(domain, **kwargs):
    from core.testers.isp_detector import detect_isp_page as _fn
    return _fn(domain, **kwargs)


def check_http_injection(domain, **kwargs):
    from core.testers.isp_detector import check_http_injection as _fn
    return _fn(domain, **kwargs)
