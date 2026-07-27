from ravshield.analyzers import create_domain_pipeline
from ravshield.enums import Severity


def test_factory_registers_domain_analyzer():
    pipeline = create_domain_pipeline()

    result = pipeline.scan("example.com")

    assert result.analysis_modules == [
        "domain_heuristics",
    ]


def test_factory_detects_suspicious_domain():
    pipeline = create_domain_pipeline()

    result = pipeline.scan(
        "xn--paypal-login-secure.zip"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "DOMAIN_PUNYCODE" in codes
    assert "DOMAIN_SUSPICIOUS_KEYWORDS" in codes
    assert "DOMAIN_SUSPICIOUS_TLD" in codes


def test_factory_preserves_finding_severity():
    pipeline = create_domain_pipeline()

    result = pipeline.scan(
        "xn--example-9d0b.com"
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.code == "DOMAIN_PUNYCODE"
    )

    assert finding.severity == Severity.HIGH


def test_factory_instances_are_independent():
    first_pipeline = create_domain_pipeline()
    second_pipeline = create_domain_pipeline()

    assert first_pipeline is not second_pipeline
    assert first_pipeline.registry is not second_pipeline.registry