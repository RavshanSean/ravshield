from ravshield.analyzers import create_email_pipeline
from ravshield.enums import Severity, Verdict
from ravshield.intel.email import (
    EmailReputationRecord,
    EmailReputationService,
)


def test_factory_registers_email_analyzers():
    pipeline = create_email_pipeline()

    result = pipeline.scan(
        "user@example.com"
    )

    assert result.analysis_modules == [
        "email_reputation",
        "email_heuristics",
    ]


def test_factory_detects_suspicious_email():
    pipeline = create_email_pipeline()

    result = pipeline.scan(
        "billing123456789012@mailinator.com"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "EMAIL_DISPOSABLE_PROVIDER" in codes
    assert "EMAIL_SUSPICIOUS_LOCAL_KEYWORDS" in codes
    assert "EMAIL_NUMERIC_HEAVY_LOCAL_PART" in codes


def test_factory_detects_known_malicious_email():
    service = EmailReputationService()

    service.add_record(
        EmailReputationRecord(
            email="scammer@example.com",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing"},
            source="unit-test",
        )
    )

    pipeline = create_email_pipeline(service)

    result = pipeline.scan(
        "scammer@example.com"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert result.verdict == Verdict.MALICIOUS
    assert "EMAIL_REPUTATION_MALICIOUS" in codes


def test_reputation_and_heuristics_combine():
    service = EmailReputationService()

    service.add_record(
        EmailReputationRecord(
            email="billing123456789012@mailinator.com",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing"},
            source="unit-test",
        )
    )

    pipeline = create_email_pipeline(service)

    result = pipeline.scan(
        "billing123456789012@mailinator.com"
    )

    codes = {
        finding.code
        for finding in result.findings
    }

    assert "EMAIL_REPUTATION_MALICIOUS" in codes
    assert "EMAIL_DISPOSABLE_PROVIDER" in codes
    assert "EMAIL_SUSPICIOUS_LOCAL_KEYWORDS" in codes
    assert "EMAIL_NUMERIC_HEAVY_LOCAL_PART" in codes

    assert result.analysis_modules == [
        "email_reputation",
        "email_heuristics",
    ]


def test_factory_instances_are_independent():
    first_pipeline = create_email_pipeline()
    second_pipeline = create_email_pipeline()

    assert first_pipeline is not second_pipeline
    assert first_pipeline.registry is not second_pipeline.registry