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


def test_normal_encoding_is_ignored():
    result = analyze_url_heuristics(
        "https://example.com/search?q=hello%20world"
    )

    assert "suspicious_encoding" not in result.signals


def test_suspicious_encoding_is_detected():
    result = analyze_url_heuristics(
        "https://example.com/%76%65%72%69%66%79"
    )

    assert "suspicious_encoding" in result.signals
    assert "encoded_unreserved" in result.details
    assert "%76" in result.details["encoded_unreserved"]


def test_keyword_substring_false_positive_is_avoided():
    result = analyze_url_heuristics(
        "https://example.com/securely-documented"
    )

    assert "suspicious_keywords" not in result.signals


def test_multiple_signals_can_be_detected():
    result = analyze_url_heuristics(
        "https://user:pass@login.verify.secure.account.example.com/%76erify"
    )

    assert "embedded_credentials" in result.signals
    assert "excessive_subdomains" in result.signals
    assert "suspicious_keywords" in result.signals
    assert "suspicious_encoding" in result.signals