import pytest

from ravshield.analyzers import EmailReputationAnalyzer
from ravshield.enums import Severity
from ravshield.intel.email import (
    EmailReputationRecord,
    EmailReputationService,
)


def test_unknown_email_returns_no_findings():
    analyzer = EmailReputationAnalyzer()

    findings = analyzer.analyze(
        "unknown@example.com"
    )

    assert findings == []


def test_known_malicious_email_returns_finding():
    service = EmailReputationService()

    service.add_record(
        EmailReputationRecord(
            email="scammer@example.com",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing", "impersonation"},
            source="unit-test",
        )
    )

    analyzer = EmailReputationAnalyzer(service)

    findings = analyzer.analyze(
        "SCAMMER@EXAMPLE.COM"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "EMAIL_REPUTATION_MALICIOUS"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 99
    assert finding.evidence["email"] == "scammer@example.com"
    assert finding.evidence["source"] == "unit-test"
    assert finding.evidence["malicious"] is True
    assert finding.evidence["tags"] == [
        "impersonation",
        "phishing",
    ]


def test_known_safe_email_returns_known_finding():
    service = EmailReputationService()

    service.add_record(
        EmailReputationRecord(
            email="safe@example.com",
            malicious=False,
            severity=Severity.INFO,
            confidence=0.88,
            tags={"trusted"},
            source="unit-test",
        )
    )

    analyzer = EmailReputationAnalyzer(service)

    findings = analyzer.analyze(
        "safe@example.com"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "EMAIL_REPUTATION_KNOWN"
    assert finding.severity == Severity.INFO
    assert finding.confidence == 88
    assert finding.evidence["malicious"] is False


def test_invalid_email_is_rejected():
    analyzer = EmailReputationAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("not-an-email")