from ravshield.intel.url import analyze_url_heuristics


def test_clean_url_has_no_signals():
    result = analyze_url_heuristics(
        "https://example.com/products"
    )

    assert result.suspicious is False
    assert result.signals == set()
    assert result.details == {}


def test_embedded_credentials_are_detected():
    result = analyze_url_heuristics(
        "https://user:password@example.com"
    )

    assert result.suspicious is True
    assert "embedded_credentials" in result.signals


def test_punycode_hostname_is_detected():
    result = analyze_url_heuristics(
        "https://xn--pple-43d.com"
    )

    assert "punycode_hostname" in result.signals


def test_excessive_subdomains_are_detected():
    result = analyze_url_heuristics(
        "https://login.verify.secure.account.example.com"
    )

    assert "excessive_subdomains" in result.signals
    assert result.details["subdomain_count"] == 4


def test_long_hostname_is_detected():
    hostname = f"{'a' * 61}.com"

    result = analyze_url_heuristics(
        f"https://{hostname}"
    )

    assert "long_hostname" in result.signals
    assert result.details["hostname_length"] == len(hostname)


def test_long_url_is_detected():
    url = "https://example.com/" + ("a" * 140)

    result = analyze_url_heuristics(url)

    assert "long_url" in result.signals
    assert result.details["url_length"] == len(url)


def test_suspicious_keywords_are_detected():
    result = analyze_url_heuristics(
        "https://example.com/account/verify-login"
    )

    assert "suspicious_keywords" in result.signals
    assert result.details["matched_keywords"] == [
        "account",
        "login",
        "verify",
    ]


def test_encoded_characters_are_detected():
    result = analyze_url_heuristics(
        "https://example.com/%76%65%72%69%66%79"
    )

    assert "encoded_characters" in result.signals


def test_multiple_signals_can_be_detected():
    result = analyze_url_heuristics(
        "https://user:pass@login.verify.secure.account.example.com/%76erify"
    )

    assert "embedded_credentials" in result.signals
    assert "excessive_subdomains" in result.signals
    assert "suspicious_keywords" in result.signals
    assert "encoded_characters" in result.signals