from ravshield.intel.email import analyze_email_heuristics


def test_clean_email_has_no_signals():
    result = analyze_email_heuristics(
        "sean@example.com"
    )

    assert result.suspicious is False
    assert result.signals == set()
    assert result.email == "sean@example.com"


def test_disposable_provider_is_detected():
    result = analyze_email_heuristics(
        "user@mailinator.com"
    )

    assert "disposable_provider" in result.signals
    assert result.details["provider"] == "mailinator.com"


def test_suspicious_local_keywords_are_detected():
    result = analyze_email_heuristics(
        "billing-security@example.com"
    )

    assert "suspicious_local_keywords" in result.signals
    assert result.details["matched_keywords"] == [
        "billing",
        "security",
    ]


def test_numeric_heavy_local_part_is_detected():
    result = analyze_email_heuristics(
        "12345678ab@example.com"
    )

    assert "numeric_heavy_local_part" in result.signals
    assert result.details["digit_ratio"] >= 0.60


def test_long_local_part_is_detected():
    local_part = "a" * 41

    result = analyze_email_heuristics(
        f"{local_part}@example.com"
    )

    assert "long_local_part" in result.signals
    assert result.details["local_part_length"] == 41


def test_punycode_domain_is_detected():
    result = analyze_email_heuristics(
        "user@xn--example-9d0b.com"
    )

    assert "punycode_domain" in result.signals


def test_free_email_provider_is_recorded_as_context():
    result = analyze_email_heuristics(
        "user@gmail.com"
    )

    assert result.details["free_email_provider"] is True
    assert result.suspicious is False


def test_multiple_signals_can_be_detected():
    result = analyze_email_heuristics(
        "billing123456789012@mailinator.com"
    )

    assert "disposable_provider" in result.signals
    assert "suspicious_local_keywords" in result.signals
    assert "numeric_heavy_local_part" in result.signals