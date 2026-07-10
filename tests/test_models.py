from ravshield.enums import Severity
from ravshield.models import DetectionFinding


def test_detection_finding_creation():
    finding = DetectionFinding(
        code="high_entropy",
        title="High entropy detected",
        description="The file may be packed, encrypted, or obfuscated.",
        severity=Severity.MEDIUM,
        confidence=75,
        evidence={"entropy": 7.8},
    )

    assert finding.code == "high_entropy"
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 75
    assert finding.evidence["entropy"] == 7.8