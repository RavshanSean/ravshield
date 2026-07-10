from ravshield.enums import Severity, Verdict
from ravshield.models import DetectionFinding
from ravshield.models import Evidence
from ravshield.models import AnalysisResult, DetectionFinding, Evidence


def test_analysis_result_creation():
    result = AnalysisResult(
        verdict=Verdict.SUSPICIOUS,
        severity=Severity.MEDIUM,
        risk_score=65,
        confidence=80,
        recommended_action="Review before opening.",
        analysis_modules=["heuristic_engine"],
    )

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.severity is Severity.MEDIUM
    assert result.risk_score == 65
    assert result.confidence == 80
    assert result.recommended_action == "Review before opening."
    assert result.analysis_modules == ["heuristic_engine"]
    assert result.findings == []
    assert result.evidence == []

def test_evidence_creation():
    evidence = Evidence(
        source="heuristic_engine",
        key="entropy",
        value=7.8,
        description="High entropy may indicate packing or encryption.",
    )

    assert evidence.source == "heuristic_engine"
    assert evidence.key == "entropy"
    assert evidence.value == 7.8
    assert evidence.description is not None


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