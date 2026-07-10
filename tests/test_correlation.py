from ravshield.engines.correlation_engine import correlate_findings
from ravshield.enums import Severity
from ravshield.models import DetectionFinding


def test_correlate_findings_combines_unique_signals():
    findings = [
        DetectionFinding(
            code="high_entropy",
            title="High entropy",
            description="Possible packing or encryption.",
            severity=Severity.MEDIUM,
            confidence=70,
        ),
        DetectionFinding(
            code="suspicious_filename",
            title="Suspicious filename",
            description="Filename contains suspicious wording.",
            severity=Severity.LOW,
            confidence=60,
        ),
    ]

    risk_score, severity = correlate_findings(findings)

    assert risk_score == 35
    assert severity is Severity.LOW


def test_correlate_findings_ignores_duplicate_codes():
    findings = [
        DetectionFinding(
            code="ioc_match",
            title="IOC match",
            description="Known malicious indicator matched.",
            severity=Severity.HIGH,
            confidence=95,
        ),
        DetectionFinding(
            code="ioc_match",
            title="Duplicate IOC match",
            description="Same indicator repeated.",
            severity=Severity.HIGH,
            confidence=95,
        ),
    ]

    risk_score, severity = correlate_findings(findings)

    assert risk_score == 45
    assert severity is Severity.MEDIUM