from ravshield.analyzers import create_domain_pipeline
from ravshield.enums import Severity, Verdict
from ravshield.intel.domain import (
    DomainReputationRecord,
    DomainReputationService,
)


def test_factory_registers_domain_analyzers():
    pipeline = create_domain_pipeline()

    result = pipeline.scan("example.com")

    assert result.analysis_modules == [
        "domain_reputation",
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


def test_factory_detects_known_malicious_domain():
    service = DomainReputationService()

    service.add_record(
        DomainReputationRecord(
            domain="evil.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"malware"},
            source="unit-test",
        )
    )

    pipeline = create_domain_pipeline(service)

    result = pipeline.scan("evil.example")

    codes = {
        finding.code
        for finding in result.findings
    }

    assert result.verdict == Verdict.MALICIOUS
    assert "DOMAIN_REPUTATION_MALICIOUS" in codes


def test_reputation_and_heuristics_combine():
    service = DomainReputationService()

    service.add_record(
        DomainReputationRecord(
            domain="xn--paypal-login-secure.zip",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing"},
            source="unit-test",
        )
    )

    pipeline = create_domain_pipeline(service)

    result = pipeline.scan(
        "xn--paypal-login-secure.zip"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "DOMAIN_REPUTATION_MALICIOUS" in codes
    assert "DOMAIN_PUNYCODE" in codes
    assert "DOMAIN_SUSPICIOUS_KEYWORDS" in codes
    assert "DOMAIN_SUSPICIOUS_TLD" in codes

    assert result.analysis_modules == [
        "domain_reputation",
        "domain_heuristics",
    ]


def test_factory_instances_are_independent():
    first_pipeline = create_domain_pipeline()
    second_pipeline = create_domain_pipeline()

    assert first_pipeline is not second_pipeline
    assert first_pipeline.registry is not second_pipeline.registry