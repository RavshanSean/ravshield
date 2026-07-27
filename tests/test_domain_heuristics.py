from ravshield.intel.domain import (
    analyze_domain_heuristics,
)


def test_clean_domain():
    result = analyze_domain_heuristics(
        "example.com"
    )
    assert result.suspicious is False
    assert result.signals == []


def test_punycode():
    result = analyze_domain_heuristics(
        "xn--paypal-123.com"
    )

    assert "punycode" in result.signals


def test_suspicious_keywords():
    result = analyze_domain_heuristics(
        "paypal-login-secure.com"
    )

    assert "suspicious_keywords" in result.signals


def test_suspicious_tld():
    result = analyze_domain_heuristics(
        "example.zip"
    )

    assert "suspicious_tld" in result.signals


def test_excessive_subdomains():
    result = analyze_domain_heuristics(
        "a.b.c.d.e.example.com"
    )

    assert "excessive_subdomains" in result.signals


def test_high_entropy():
    result = analyze_domain_heuristics(
        "q7m2x9v4k8p3z6n5r1t0.com"
    )

    assert "high_entropy" in result.signals


def test_multiple_signals():
    result = analyze_domain_heuristics(
        "xn--paypal-login-secure.zip"
    )

    assert "punycode" in result.signals
    assert "suspicious_keywords" in result.signals
    assert "suspicious_tld" in result.signals