import pytest

from ravshield.analyzers import URLAnalyzer
from ravshield.intel.url import (
    URLReputationRecord,
    URLReputationService,
)
from ravshield.enums import Severity


def test_unknown_url_returns_no_findings():
    analyzer = URLAnalyzer()

    findings = analyzer.analyze(
        "https://unknown.example"
    )

    assert findings == []


def test_known_malicious_url():
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url="https://evil.example",
            malicious=True,
            severity=Severity.CRITICAL,
            confidence=0.98,
            tags={"phishing"},
            source="unit-test",
        )
    )

    analyzer = URLAnalyzer(service)

    findings = analyzer.analyze(
        "https://evil.example"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "URL_REPUTATION_MALICIOUS"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 98
    assert finding.evidence["url"] == "https://evil.example/"
    assert finding.evidence["source"] == "unit-test"
    assert finding.evidence["malicious"] is True
    assert "phishing" in finding.evidence["tags"]


def test_known_safe_url():
    service = URLReputationService()

    service.add_record(
        URLReputationRecord(
            url="https://safe.example",
            malicious=False,
            severity=Severity.INFO,
            confidence=0.80,
            source="unit-test",
        )
    )

    analyzer = URLAnalyzer(service)

    findings = analyzer.analyze(
        "https://safe.example"
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "URL_REPUTATION_KNOWN"
    assert finding.severity == Severity.INFO
    assert finding.confidence == 80
    assert finding.evidence["malicious"] is False


def test_private_ip_still_rejected():
    analyzer = URLAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(
            "http://192.168.1.100"
        )