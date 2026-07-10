from ravshield.enums import Severity, Verdict


def test_verdict_values():
    assert Verdict.SAFE.value == "safe"
    assert Verdict.SUSPICIOUS.value == "suspicious"
    assert Verdict.MALICIOUS.value == "malicious"
    assert Verdict.UNKNOWN.value == "unknown"


def test_severity_values():
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"