import pytest

from ravshield.analyzers import IPReputationAnalyzer
from ravshield.enums import Severity
from ravshield.intel.ip import (
    IPReputationRecord,
    IPReputationService,
)


def test_unknown_ip_returns_no_findings():
    analyzer = IPReputationAnalyzer()

    findings = analyzer.analyze("8.8.8.8")

    assert findings == []


def test_known_malicious_ip_returns_finding():
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="203.0.113.10",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.99,
            tags={"botnet", "c2"},
            source="unit-test",
        )
    )

    analyzer = IPReputationAnalyzer(service)

    findings = analyzer.analyze("203.0.113.10")

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "IP_REPUTATION_MALICIOUS"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 99
    assert finding.evidence["ip"] == "203.0.113.10"
    assert finding.evidence["source"] == "unit-test"
    assert finding.evidence["malicious"] is True
    assert finding.evidence["tags"] == [
        "botnet",
        "c2",
    ]


def test_known_safe_ip_returns_known_finding():
    service = IPReputationService()

    service.add_record(
        IPReputationRecord(
            ip="1.1.1.1",
            malicious=False,
            severity=Severity.INFO,
            confidence=0.88,
            tags={"trusted"},
            source="unit-test",
        )
    )

    analyzer = IPReputationAnalyzer(service)

    findings = analyzer.analyze("1.1.1.1")

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "IP_REPUTATION_KNOWN"
    assert finding.severity == Severity.INFO
    assert finding.confidence == 88
    assert finding.evidence["malicious"] is False


def test_invalid_ip_is_rejected():
    analyzer = IPReputationAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze("not-an-ip")