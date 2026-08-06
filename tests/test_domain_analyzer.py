from ravshield.analyzers import DomainReputationAnalyzer
from ravshield.enums import Severity
from ravshield.intel.domain import (
    DomainReputationRecord,
    DomainReputationService,
)


def test_unknown_domain_returns_no_findings():
    analyzer = DomainReputationAnalyzer()

    findings = analyzer.analyze(
        "unknown.example"
    )

    assert findings == []


def test_known_malicious_domain_returns_finding():
    service = DomainReputationService()

    service.add_record(
        DomainReputationRecord(
            domain="evil.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"phishing", "malware"},
            source="unit-test",
        )
    )

    analyzer = DomainReputationAnalyzer(service)

    findings = analyzer.analyze(
        "EVIL.EXAMPLE."
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "DOMAIN_REPUTATION_MALICIOUS"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 99
    assert finding.evidence["domain"] == "evil.example"
    assert finding.evidence["source"] == "unit-test"
    assert finding.evidence["malicious"] is True
    assert finding.evidence["tags"] == [
        "malware",
        "phishing",
    ]


def test_known_safe_domain_returns_known_finding():
    service = DomainReputationService()

    service.add_record(
        DomainReputationRecord(
            domain="safe.example",
            malicious=False,
            severity=Severity.INFO,
            confidence=0.85,
            tags={"trusted"},
            source="unit-test",
        )
    )

    analyzer = DomainReputationAnalyzer(service)

    findings = analyzer.analyze(
        "safe.example"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "DOMAIN_REPUTATION_KNOWN"
    assert finding.severity == Severity.INFO
    assert finding.confidence == 85
    assert finding.evidence["malicious"] is False


def test_invalid_domain_is_rejected():
    analyzer = DomainReputationAnalyzer()

    try:
        analyzer.analyze("not-a-valid-domain")
    except ValueError as error:
        assert str(error) == "Invalid domain."
    else:
        raise AssertionError(
            "Expected invalid domain to raise ValueError."
        )